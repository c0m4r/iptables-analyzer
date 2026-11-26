//go:build linux

package analyzer

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The tests in this file compare the trace of a packet with what the kernel
// does with a real one. A ruleset is loaded with iptables-restore in a new
// network namespace; other namespaces stand for the hosts around it, and
// real connections show which of them answers.
//
// Nothing here needs root: the namespaces belong to a new user namespace.
// The test binary runs itself in them (kernelRole says in which part), so the
// only tools from outside are ip and iptables-restore. Where user namespaces
// or these tools are not available, the tests are skipped.

const kernelRole = "IPTABLES_ANALYZER_KERNEL_TEST"

func TestMain(m *testing.M) {
	switch os.Getenv(kernelRole) {
	case "host":
		os.Exit(kernelHost())
	case "peer":
		os.Exit(kernelPeer())
	}
	os.Exit(m.Run())
}

// kernelNet is a network at one interface of the host under test.
type kernelNet struct {
	// Iface is the name of the interface on the host. The rules name it.
	Iface string
	// HostAddr is the address of the host there, with the prefix length.
	HostAddr string
	// Peers are the addresses of the namespace at the other end. A network of
	// clients sends the probes from them; a network behind the host listens
	// on them. Addresses outside the network of HostAddr are routed to the
	// first peer.
	Peers []string
	// Hosts are more addresses in that namespace. They listen, also in a
	// network of clients: the hosts of a local network that the host under
	// test sends ports to.
	Hosts []string
	// Forged are addresses in that namespace to which the host under test
	// has no route through this interface: probes from them arrive where the
	// way back does not lead.
	Forged []string
}

// kernelProbe is one connection attempt. The protocol "udp1" sends one
// datagram and waits for no answer; the host under test then says whether a
// socket received it. That shows what the rules do with packets whose
// answer cannot come back.
type kernelProbe struct {
	Protocol    string
	Source      string
	Destination string
	Port        int
}

func (p kernelProbe) String() string {
	return fmt.Sprintf("%s %s -> %s:%d", p.Protocol, p.Source, p.Destination, p.Port)
}

// kernelScenario is a ruleset with the networks around the host.
type kernelScenario struct {
	Rules string
	// IPv6 says that the rules are for ip6tables and that the addresses of
	// the networks are IPv6 addresses.
	IPv6    bool
	Clients []kernelNet
	Inner   []kernelNet
	// Forward turns on the routing of packets between the interfaces, and
	// RouteLocalnet the delivery of packets from other hosts to 127.0.0.0/8.
	Forward       bool
	RouteLocalnet bool
	// RPFilter is the mode of the reverse-path filter: 0 when empty.
	RPFilter string
	Probes   []kernelProbe
	// HostPorts and InnerPorts are the ports with a listener on the host and
	// on every address behind it.
	HostPorts  []int
	InnerPorts []int
}

// kernelRequest is what the namespaces are asked to do, and kernelReply what
// they answer.
type kernelRequest struct {
	Op     string // run, listen, probe
	Args   []string
	Name   string
	Addrs  []string
	Ports  []int
	Probes []kernelProbe
}

type kernelReply struct {
	Err     string
	Results []string
}

const kernelTimeout = 700 * time.Millisecond

// kernelReceived holds the datagrams that the sockets of the host under
// test received, as "source port". The port is the one that the client sent
// to, which the datagram names: a rule can have sent it to a different one.
var kernelReceived sync.Map

// listen answers every connection and datagram on the ports with
// "name:port". name is the address for a listener on one address, and
// "host" for the listeners of the host under test.
func kernelListen(name, addr string, ports []int, tcp bool) error {
	family := kernelFamily(addr)
	for _, port := range ports {
		banner := []byte(name + ":" + strconv.Itoa(port))
		endpoint := net.JoinHostPort(addr, strconv.Itoa(port))
		if tcp {
			listener, err := net.Listen("tcp"+family, endpoint)
			if err != nil {
				return err
			}
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					conn.Write(banner)
					conn.Close()
				}
			}()
		}
		// A datagram socket on the wildcard address answers from the address
		// of the egress interface, which is not always the one that the client
		// sent to. The sockets for datagrams are bound to one address each.
		if addr == "0.0.0.0" || addr == "::" {
			continue
		}
		socket, err := net.ListenPacket("udp"+family, endpoint)
		if err != nil {
			return err
		}
		go func() {
			buffer := make([]byte, 64)
			for {
				n, from, err := socket.ReadFrom(buffer)
				if err != nil {
					return
				}
				if sender, ok := from.(*net.UDPAddr); ok {
					kernelReceived.Store(sender.IP.String()+" "+strings.TrimPrefix(string(buffer[:n]), "probe "), true)
				}
				socket.WriteTo(banner, from)
			}
		}()
	}
	return nil
}

// kernelFamily returns the suffix of the Go network names for an address:
// "4" or "6".
func kernelFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "6"
	}
	return "4"
}

// kernelConnect sends one probe and says what came back: "open name:port",
// "rejected" or "timeout".
func kernelConnect(probe kernelProbe) string {
	family := kernelFamily(probe.Source)
	local := net.JoinHostPort(probe.Source, "0")
	remote := net.JoinHostPort(probe.Destination, strconv.Itoa(probe.Port))
	var dialer net.Dialer
	dialer.Timeout = kernelTimeout
	network := probe.Protocol
	if network == "udp" || network == "udp1" {
		network = "udp"
		dialer.LocalAddr, _ = net.ResolveUDPAddr("udp"+family, local)
	} else {
		dialer.LocalAddr, _ = net.ResolveTCPAddr("tcp"+family, local)
	}
	conn, err := dialer.Dial(network+family, remote)
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return "timeout"
		}
		return "rejected"
	}
	defer conn.Close()
	if network == "udp" {
		if _, err := conn.Write([]byte("probe " + strconv.Itoa(probe.Port))); err != nil {
			return "rejected"
		}
	}
	if probe.Protocol == "udp1" {
		return "sent"
	}
	conn.SetReadDeadline(time.Now().Add(kernelTimeout))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if n > 0 {
		return "open " + string(buffer[:n])
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "rejected"
}

// kernelServe carries out the requests that arrive on standard input.
func kernelServe(handle func(kernelRequest) kernelReply) int {
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	encoder := json.NewEncoder(os.Stdout)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return 0
		}
		var request kernelRequest
		if err := json.Unmarshal(line, &request); err != nil {
			encoder.Encode(kernelReply{Err: err.Error()})
			continue
		}
		encoder.Encode(handle(request))
	}
}

func kernelRun(args []string, stdin string) error {
	path, err := exec.LookPath(args[0])
	if err != nil {
		for _, dir := range []string{"/usr/sbin", "/sbin"} {
			if _, statErr := os.Stat(dir + "/" + args[0]); statErr == nil {
				path, err = dir+"/"+args[0], nil
			}
		}
	}
	if err != nil {
		return err
	}
	command := exec.Command(path, args[1:]...)
	command.Stdin = strings.NewReader(stdin)
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// kernelPeer is a namespace next to the host: it sets up its interface,
// listens, and sends probes.
func kernelPeer() int {
	return kernelServe(func(request kernelRequest) kernelReply {
		switch request.Op {
		case "run":
			if err := kernelRun(request.Args, ""); err != nil {
				return kernelReply{Err: err.Error()}
			}
		case "listen":
			for _, addr := range request.Addrs {
				if err := kernelListen(addr, addr, request.Ports, true); err != nil {
					return kernelReply{Err: err.Error()}
				}
			}
		case "probe":
			results := make([]string, len(request.Probes))
			var group sync.WaitGroup
			slots := make(chan struct{}, 48)
			for i, probe := range request.Probes {
				group.Add(1)
				go func() {
					defer group.Done()
					slots <- struct{}{}
					results[i] = kernelConnect(probe)
					<-slots
				}()
			}
			group.Wait()
			return kernelReply{Results: results}
		}
		return kernelReply{}
	})
}

// kernelLink is a running namespace with the pipe to it.
type kernelLink struct {
	command *exec.Cmd
	stdin   *json.Encoder
	stdout  *bufio.Reader
}

func (l *kernelLink) ask(request kernelRequest) (kernelReply, error) {
	var reply kernelReply
	if err := l.stdin.Encode(request); err != nil {
		return reply, err
	}
	line, err := l.stdout.ReadBytes('\n')
	if err != nil {
		return reply, err
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		return reply, err
	}
	if reply.Err != "" {
		return reply, errors.New(reply.Err)
	}
	return reply, nil
}

// kernelSpawn starts the test binary in new namespaces.
func kernelSpawn(role string, flags uintptr, user bool) (*kernelLink, error) {
	command := exec.Command("/proc/self/exe")
	command.Env = append(os.Environ(), kernelRole+"="+role)
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags, Pdeathsig: syscall.SIGKILL}
	if user {
		command.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		command.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &kernelLink{command: command, stdin: json.NewEncoder(stdin), stdout: bufio.NewReaderSize(stdout, 1<<20)}, nil
}

// kernelHost is the host under test: it builds the networks, loads the
// rules, listens, and has the clients send the probes.
func kernelHost() int {
	return kernelServe(func(request kernelRequest) kernelReply {
		var scenario kernelScenario
		if err := json.Unmarshal([]byte(request.Name), &scenario); err != nil {
			return kernelReply{Err: err.Error()}
		}
		results, err := kernelScenarioRun(scenario)
		if err != nil {
			return kernelReply{Err: err.Error()}
		}
		return kernelReply{Results: results}
	})
}

func kernelScenarioRun(scenario kernelScenario) ([]string, error) {
	run := func(args ...string) error { return kernelRun(args, "") }
	if err := run("ip", "link", "set", "lo", "up"); err != nil {
		return nil, err
	}
	// Replies must leave through the interface of the probe, whatever the
	// sysctl settings of the machine are.
	sysctl := func(path, value string) {
		os.WriteFile("/proc/sys/net/ipv4/"+path, []byte(value), 0o644)
	}
	onOff := map[bool]string{false: "0", true: "1"}
	reversePath := scenario.RPFilter
	if reversePath == "" {
		reversePath = "0"
	}
	sysctl("conf/all/rp_filter", reversePath)
	sysctl("conf/default/rp_filter", reversePath)
	sysctl("conf/all/route_localnet", onOff[scenario.RouteLocalnet])
	sysctl("conf/default/route_localnet", "0")
	sysctl("ip_forward", onOff[scenario.Forward])
	// The kernel limits how many ICMP errors it sends. Many probes meet a
	// REJECT rule at the same time here, and a refusal that the limit holds
	// back would look like a dropped packet.
	sysctl("icmp_ratelimit", "0")
	sysctl("icmp_msgs_per_sec", "100000")
	sysctl("icmp_msgs_burst", "10000")
	os.WriteFile("/proc/sys/net/ipv6/icmp/ratelimit", []byte("0"), 0o644)
	// What differs for IPv6: the tool that loads the rules, the length of a
	// single address, and the addresses of the host itself.
	restore, single, loopback, wildcard := "iptables-restore", "32", "127.0.0.1", "0.0.0.0"
	var nodad, route6 []string
	sysctl6 := func(path, value string) {
		os.WriteFile("/proc/sys/net/ipv6/"+path, []byte(value), 0o644)
	}
	if scenario.IPv6 {
		restore, single, loopback, wildcard = "ip6tables-restore", "128", "::1", "::"
		// An address is used at once, without the wait for duplicate address
		// detection.
		nodad, route6 = []string{"nodad"}, []string{"-6"}
		for _, scope := range []string{"all", "default"} {
			sysctl6("conf/"+scope+"/disable_ipv6", "0")
			sysctl6("conf/"+scope+"/accept_dad", "0")
			sysctl6("conf/"+scope+"/forwarding", onOff[scenario.Forward])
		}
	}

	var peers []*kernelLink
	defer func() {
		for _, peer := range peers {
			peer.command.Process.Kill()
			peer.command.Wait()
		}
	}()
	sourceOf := map[string]*kernelLink{}
	attach := func(index int, network kernelNet, client bool) (*kernelLink, error) {
		peer, err := kernelSpawn("peer", syscall.CLONE_NEWNET, false)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
		far := fmt.Sprintf("p%d", index)
		// The far end has a known hardware address: for IPv6 the neighbors
		// are entered ahead (see below).
		farMAC := fmt.Sprintf("02:00:00:00:%02x:02", index)
		host, bits, _ := strings.Cut(network.HostAddr, "/")
		steps := [][]string{
			{"ip", "link", "add", network.Iface, "type", "veth", "peer", "name", far, "address", farMAC},
			{"ip", "link", "set", far, "netns", strconv.Itoa(peer.command.Process.Pid)},
			append([]string{"ip", "addr", "add", network.HostAddr, "dev", network.Iface}, nodad...),
			{"ip", "link", "set", network.Iface, "up"},
		}
		for _, step := range steps {
			if err := run(step...); err != nil {
				return nil, err
			}
		}
		sysctl("conf/"+network.Iface+"/rp_filter", reversePath)
		if scenario.IPv6 {
			sysctl6("conf/"+network.Iface+"/forwarding", onOff[scenario.Forward])
		}
		inside := [][]string{{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", far, "up"}}
		_, subnet, _ := net.ParseCIDR(network.HostAddr)
		for _, addr := range append(append(append([]string{}, network.Peers...), network.Hosts...), network.Forged...) {
			length := single
			if subnet.Contains(net.ParseIP(addr)) {
				length = bits
			}
			inside = append(inside, append([]string{"ip", "addr", "add", addr + "/" + length, "dev", far}, nodad...))
			// IPv6 finds its neighbors with ICMPv6 packets, which pass the
			// rules under test. Rules that drop them stop all traffic; the
			// tool reports that as a finding of its own. Here the neighbors
			// are entered ahead, so that the probes show what the rules do
			// with the connections themselves.
			if scenario.IPv6 {
				if err := run("ip", "neigh", "replace", addr, "lladdr", farMAC, "dev", network.Iface, "nud", "permanent"); err != nil {
					return nil, err
				}
			}
		}
		inside = append(inside, append(append([]string{"ip"}, route6...), "route", "add", "default", "via", host, "dev", far))
		// The address of the host is resolved ahead. The reverse-path filter
		// also refuses the ARP requests of a forged source, and a request that
		// stays without an answer would hold back the other probes.
		if link, err := net.InterfaceByName(network.Iface); err == nil {
			inside = append(inside, []string{"ip", "neigh", "replace", host, "lladdr", link.HardwareAddr.String(), "dev", far, "nud", "permanent"})
		}
		for _, step := range inside {
			if _, err := peer.ask(kernelRequest{Op: "run", Args: step}); err != nil {
				return nil, err
			}
		}
		for _, addr := range network.Forged {
			sourceOf[addr] = peer
		}
		for _, addr := range network.Peers {
			if client {
				sourceOf[addr] = peer
			}
			if !subnet.Contains(net.ParseIP(addr)) {
				if err := run("ip", "route", "add", addr+"/"+single, "via", network.Peers[0], "dev", network.Iface); err != nil {
					return nil, err
				}
			}
		}
		return peer, nil
	}
	index := 0
	for _, network := range scenario.Clients {
		peer, err := attach(index, network, true)
		if err != nil {
			return nil, err
		}
		index++
		if len(network.Hosts) > 0 {
			if _, err := peer.ask(kernelRequest{Op: "listen", Addrs: network.Hosts, Ports: scenario.InnerPorts}); err != nil {
				return nil, err
			}
		}
	}
	for _, network := range scenario.Inner {
		peer, err := attach(index, network, false)
		if err != nil {
			return nil, err
		}
		index++
		if _, err := peer.ask(kernelRequest{Op: "listen", Addrs: network.Peers, Ports: scenario.InnerPorts}); err != nil {
			return nil, err
		}
	}
	if err := kernelRun([]string{restore}, scenario.Rules); err != nil {
		return nil, err
	}
	if err := kernelListen("host", wildcard, scenario.HostPorts, true); err != nil {
		return nil, err
	}
	own := []string{loopback}
	for _, network := range append(append([]kernelNet{}, scenario.Clients...), scenario.Inner...) {
		addr, _, _ := strings.Cut(network.HostAddr, "/")
		own = append(own, addr)
	}
	for _, addr := range own {
		if err := kernelListen("host", addr, scenario.HostPorts, false); err != nil {
			return nil, err
		}
	}

	// Every client sends its probes at once; the results keep their places.
	results := make([]string, len(scenario.Probes))
	batches := map[*kernelLink][]int{}
	for i, probe := range scenario.Probes {
		peer := sourceOf[probe.Source]
		if peer == nil {
			return nil, fmt.Errorf("no client has the source address %s", probe.Source)
		}
		batches[peer] = append(batches[peer], i)
	}
	for peer, indexes := range batches {
		request := kernelRequest{Op: "probe"}
		for _, i := range indexes {
			request.Probes = append(request.Probes, scenario.Probes[i])
		}
		reply, err := peer.ask(request)
		if err != nil {
			return nil, err
		}
		for j, i := range indexes {
			results[i] = reply.Results[j]
		}
	}
	// Datagrams that needed no answer: did a socket receive them?
	time.Sleep(200 * time.Millisecond)
	for i, probe := range scenario.Probes {
		if probe.Protocol != "udp1" {
			continue
		}
		results[i] = "lost"
		if _, received := kernelReceived.Load(probe.Source + " " + strconv.Itoa(probe.Port)); received {
			results[i] = "delivered"
		}
	}
	return results, nil
}

// kernelSkip says why the kernel tests cannot run here, or "".
func kernelSkip(ipv6 bool) string {
	tools := []string{"ip", "iptables-restore"}
	if ipv6 {
		tools = []string{"ip", "ip6tables-restore"}
		if _, err := os.Stat("/proc/sys/net/ipv6/conf/all/forwarding"); err != nil {
			return "this kernel runs without IPv6"
		}
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			found := false
			for _, dir := range []string{"/usr/sbin", "/sbin"} {
				if _, err := os.Stat(dir + "/" + tool); err == nil {
					found = true
				}
			}
			if !found {
				return tool + " is not installed"
			}
		}
	}
	return ""
}

// kernelObserve loads the rules of a scenario in a namespace and returns
// what each probe met.
func kernelObserve(t *testing.T, scenario kernelScenario) []string {
	t.Helper()
	host, err := kernelSpawn("host", syscall.CLONE_NEWUSER|syscall.CLONE_NEWNET, true)
	if err != nil {
		t.Skipf("no user and network namespace is available: %v", err)
	}
	defer func() {
		host.command.Process.Kill()
		host.command.Wait()
	}()
	encoded, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := host.ask(kernelRequest{Name: string(encoded)})
	if err != nil {
		if strings.Contains(err.Error(), "tables-restore") {
			t.Fatalf("the rules do not load: %v", err)
		}
		t.Skipf("the namespaces cannot be set up: %v", err)
	}
	return reply.Results
}

// kernelCompare traces every probe of a scenario, sends the probes through
// the real rules, and reports the probes for which the two differ. It
// returns the number of probes whose trace gave a certain verdict.
func kernelCompare(t *testing.T, scenario kernelScenario) int {
	t.Helper()
	if testing.Short() {
		t.Skip("runs external tools in network namespaces")
	}
	if reason := kernelSkip(scenario.IPv6); reason != "" {
		t.Skip(reason)
	}
	version, loopback := models.IPv4, "127.0.0.1/8"
	if scenario.IPv6 {
		version, loopback = models.IPv6, "::1/128"
	}
	rs := mustParse(t, scenario.Rules, version)
	onOff := map[bool]string{false: "0", true: "1"}
	host := &models.HostContext{
		Interfaces: []models.HostInterface{{Name: "lo", Addrs: []string{loopback}, Up: true}},
		Sysctls: map[string]string{
			"net.ipv4.ip_forward":              onOff[scenario.Forward],
			"net.ipv4.conf.all.route_localnet": onOff[scenario.RouteLocalnet],
			"net.ipv6.conf.all.forwarding":     onOff[scenario.Forward],
		},
	}
	ifaceOf := map[string]string{}
	inner := map[string]bool{}
	for _, network := range scenario.Clients {
		host.Interfaces = append(host.Interfaces, models.HostInterface{Name: network.Iface, Addrs: []string{network.HostAddr}, Up: true})
		host.Sysctls["net.ipv4.conf."+network.Iface+".route_localnet"] = "0"
		for _, addr := range append(append([]string{}, network.Peers...), network.Forged...) {
			ifaceOf[addr] = network.Iface
		}
		for _, addr := range network.Hosts {
			inner[addr] = true
		}
	}
	// The routes that the scenario sets up, and the reverse-path filter.
	host.RoutesKnown = !scenario.IPv6
	reversePath := scenario.RPFilter
	if reversePath == "" {
		reversePath = "0"
	}
	host.Sysctls["net.ipv4.conf.all.rp_filter"] = reversePath
	for _, network := range append(append([]kernelNet{}, scenario.Clients...), scenario.Inner...) {
		host.Sysctls["net.ipv4.conf."+network.Iface+".rp_filter"] = reversePath
		if scenario.IPv6 {
			continue // the routes are read for IPv4 only
		}
		_, subnet, _ := net.ParseCIDR(network.HostAddr)
		host.Routes = append(host.Routes, models.Route{Destination: subnet.String(), Devices: []string{network.Iface}})
		for _, addr := range network.Peers {
			if !subnet.Contains(net.ParseIP(addr)) {
				host.Routes = append(host.Routes, models.Route{Destination: addr + "/32", Devices: []string{network.Iface}})
			}
		}
	}
	for _, network := range scenario.Inner {
		host.Interfaces = append(host.Interfaces, models.HostInterface{Name: network.Iface, Addrs: []string{network.HostAddr}, Up: true})
		host.Sysctls["net.ipv4.conf."+network.Iface+".route_localnet"] = "0"
		for _, addr := range network.Peers {
			inner[addr] = true
		}
	}

	// A listener waits wherever a packet can arrive, so that the answer tells
	// who received it.
	hostPorts, innerPorts := map[int]bool{}, map[int]bool{}
	traces := make([]*models.Trace, len(scenario.Probes))
	for i, probe := range scenario.Probes {
		traces[i] = Trace(rs, host, models.Packet{
			Protocol: models.Protocol(strings.TrimSuffix(probe.Protocol, "1")), Source: probe.Source, Destination: probe.Destination,
			Port: probe.Port, In: ifaceOf[probe.Source], State: "NEW",
		})
		hostPorts[probe.Port], innerPorts[probe.Port] = true, true
		if port := traces[i].Port; port != 0 {
			hostPorts[port], innerPorts[port] = true, true
		}
	}
	for port := range hostPorts {
		scenario.HostPorts = append(scenario.HostPorts, port)
	}
	for port := range innerPorts {
		scenario.InnerPorts = append(scenario.InnerPorts, port)
	}

	observed := kernelObserve(t, scenario)
	// expected says what a client meets at the end of a way.
	expected := func(verdict, delivery, destination string, port int) []string {
		switch {
		case verdict == "DROP":
			return []string{"timeout"}
		case verdict == "REJECT":
			return []string{"rejected"}
		case delivery == "local":
			return []string{"open host:" + strconv.Itoa(port)}
		case inner[destination]:
			return []string{"open " + destination + ":" + strconv.Itoa(port)}
		}
		// The rules send the packet on to an address that has no host in this
		// scenario. What comes back depends on the routes, not on the rules;
		// only an answer would be wrong.
		return []string{"timeout", "rejected"}
	}
	certain := 0
	seen := map[string]int{}
	for i, probe := range scenario.Probes {
		trace := traces[i]
		// With -v the test shows what the kernel did, probe by probe.
		kind, _, _ := strings.Cut(observed[i], " ")
		seen[kind]++
		t.Logf("%-58s kernel: %-24s trace: %s %s", probe.String(), observed[i], trace.Verdict, trace.Delivery)
		if !trace.Certain {
			continue
		}
		// The verdict is certain; where rules share the packets among several
		// destinations, the kernel picks one of them.
		want := expected(trace.Verdict, trace.Delivery, trace.Destination, trace.Port)
		for _, other := range trace.Alternatives {
			want = append(want, expected(other.Verdict, other.Delivery, other.Destination, other.Port)...)
		}
		if probe.Protocol == "udp1" {
			// Only the arrival at a socket of the host is observed.
			want = []string{"lost"}
			if trace.Verdict == "ACCEPT" && trace.Delivery == "local" {
				want = []string{"delivered"}
			}
		}
		certain++
		if !containsString(want, observed[i]) {
			t.Errorf("%s (in %s)\n    trace:  %s by %s -> %s\n    kernel: %s", probe, ifaceOf[probe.Source],
				trace.Verdict, trace.DecidedBy, strings.Join(want, " or "), observed[i])
		}
	}
	if seen["open"]+seen["delivered"] == 0 && len(scenario.Probes) > 12 {
		// No connection at all came through: the networks of the test do not
		// work, and a comparison of refusals alone would prove nothing.
		t.Errorf("no probe reached a listener: %v", seen)
	}
	return certain
}
