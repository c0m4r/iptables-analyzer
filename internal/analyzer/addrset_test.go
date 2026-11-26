package analyzer

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/models"
)

// The set operations are compared with plain membership tables over a small
// address space. universeBits is large enough for sets of several chunks.
const universeBits = 12

var universeBase = netip.MustParseAddr("10.20.0.0")

func universeAddr(i int) netip.Addr {
	b := universeBase.As4()
	b[2] |= byte(i >> 8)
	b[3] = byte(i)
	return netip.AddrFrom4(b)
}

type membership []bool

func randomMembership(r *rand.Rand) membership {
	m := make(membership, 1<<universeBits)
	switch r.Intn(4) {
	case 0: // a few prefixes
		for n := r.Intn(6); n > 0; n-- {
			bits := r.Intn(universeBits + 1)
			start := r.Intn(1<<universeBits) &^ (1<<(universeBits-bits) - 1)
			for i := start; i < start+1<<(universeBits-bits); i++ {
				m[i] = true
			}
		}
	case 1: // many single addresses: more ranges than one chunk holds
		for i := range m {
			m[i] = r.Intn(3) == 0
		}
	case 2: // everything but a few addresses, like a blocklist leaves it
		for i := range m {
			m[i] = true
		}
		for n := r.Intn(700); n > 0; n-- {
			m[r.Intn(len(m))] = false
		}
	}
	return m
}

func (m membership) set() addrSet {
	var ranges []addrRange
	for i := 0; i < len(m); i++ {
		if !m[i] {
			continue
		}
		j := i
		for j+1 < len(m) && m[j+1] {
			j++
		}
		ranges = append(ranges, addrRange{lo: universeAddr(i), hi: universeAddr(j)})
		i = j
	}
	return makeSet(ranges)
}

func checkSet(t *testing.T, what string, got addrSet, want membership) {
	t.Helper()
	ranges := got.ranges()
	for i, r := range ranges {
		if r.lo.Compare(r.hi) > 0 {
			t.Fatalf("%s: inverted range %v-%v", what, r.lo, r.hi)
		}
		if i > 0 && touches(ranges[i-1], r) {
			t.Fatalf("%s: ranges %v-%v and %v-%v overlap or touch", what, ranges[i-1].lo, ranges[i-1].hi, r.lo, r.hi)
		}
	}
	for _, chunk := range got.chunks {
		if len(chunk) == 0 {
			t.Fatalf("%s: empty chunk", what)
		}
	}
	count := 0
	for i, member := range want {
		if got.contains(universeAddr(i)) != member {
			t.Fatalf("%s: address %v: got %v, want %v", what, universeAddr(i), !member, member)
		}
		if member {
			count++
		}
	}
	if size := got.size(); size.hi != 0 || size.lo != uint64(count) {
		t.Fatalf("%s: size %v, want %d", what, size, count)
	}
	if got.empty() != (count == 0) {
		t.Fatalf("%s: empty() = %v with %d addresses", what, got.empty(), count)
	}
}

func TestAddrSetOperationsMatchMembershipTables(t *testing.T) {
	r := rand.New(rand.NewSource(20261125))
	for round := 0; round < 100; round++ {
		a, b := randomMembership(r), randomMembership(r)
		sa, sb := a.set(), b.set()
		checkSet(t, "set", sa, a)

		union, minus, both := make(membership, len(a)), make(membership, len(a)), make(membership, len(a))
		overlap := false
		for i := range a {
			union[i], minus[i], both[i] = a[i] || b[i], a[i] && !b[i], a[i] && b[i]
			overlap = overlap || both[i]
		}
		checkSet(t, "union", sa.union(sb), union)
		checkSet(t, "subtract", sa.subtract(sb), minus)
		checkSet(t, "intersect", sa.intersect(sb), both)
		if sa.overlaps(sb) != overlap {
			t.Fatalf("overlaps: got %v, want %v", !overlap, overlap)
		}
		if !sa.union(sb).equal(sb.union(sa)) || !sa.equal(sa.union(sa)) || !sa.subtract(sa).empty() {
			t.Fatal("union and subtract are not consistent")
		}

		// split by a random prefix of the universe, and by one that covers it.
		bits := r.Intn(universeBits + 1)
		start := r.Intn(1<<universeBits) &^ (1<<(universeBits-bits) - 1)
		prefix := netip.PrefixFrom(universeAddr(start), 32-universeBits+bits)
		in, out := make(membership, len(a)), make(membership, len(a))
		inside := false
		for i := range a {
			covered := i >= start && i < start+1<<(universeBits-bits)
			in[i], out[i] = a[i] && covered, a[i] && !covered
			inside = inside || in[i]
		}
		gotIn, gotOut := sa.split(prefix)
		checkSet(t, "split inside "+prefix.String(), gotIn, in)
		checkSet(t, "split outside "+prefix.String(), gotOut, out)
		if sa.overlapsPrefix(prefix) != inside {
			t.Fatalf("overlapsPrefix(%v): got %v, want %v", prefix, !inside, inside)
		}
		if all, none := sa.split(netip.MustParsePrefix("10.0.0.0/8")); !all.equal(sa) || !none.empty() {
			t.Fatal("split by a prefix that contains the set")
		}
		if none, all := sa.split(netip.MustParsePrefix("192.0.2.0/24")); !all.equal(sa) || !none.empty() {
			t.Fatal("split by a prefix outside the set")
		}

		// The prefixes cover exactly the set, without overlap.
		covered := make(membership, len(a))
		for _, p := range sa.prefixes() {
			if p != p.Masked() {
				t.Fatalf("prefix %v is not canonical", p)
			}
			for i := range covered {
				if p.Contains(universeAddr(i)) {
					if covered[i] {
						t.Fatalf("address %v is in two prefixes", universeAddr(i))
					}
					covered[i] = true
				}
			}
		}
		for i := range a {
			if covered[i] != a[i] {
				t.Fatalf("prefixes() does not cover the set at %v", universeAddr(i))
			}
		}
	}
}

func TestAddrSetWholeAddressSpaces(t *testing.T) {
	for _, tt := range []struct {
		version int
		all     string
		one     string
		parts   int
	}{{4, "0.0.0.0/0", "203.0.113.7/32", 32}, {6, "::/0", "2001:db8::1/128", 128}} {
		all := setOfPrefix(netip.MustParsePrefix(tt.all))
		if got := all.prefixes(); len(got) != 1 || got[0].String() != tt.all {
			t.Fatalf("IPv%d: prefixes of the whole space: %v", tt.version, got)
		}
		one := netip.MustParsePrefix(tt.one)
		inside, outside := all.split(one)
		if got := inside.prefixes(); len(got) != 1 || got[0] != one {
			t.Fatalf("IPv%d: inside: %v", tt.version, got)
		}
		// Everything but one address is two ranges, and as many prefixes as
		// the address has bits.
		if len(outside.ranges()) != 2 || len(outside.prefixes()) != tt.parts {
			t.Fatalf("IPv%d: outside has %d ranges and %d prefixes", tt.version, len(outside.ranges()), len(outside.prefixes()))
		}
		if !outside.union(inside).equal(all) || outside.contains(one.Addr()) || !all.contains(one.Addr()) {
			t.Fatalf("IPv%d: split and union do not round-trip", tt.version)
		}
	}
	if setOfPrefix(netip.MustParsePrefix("::/0")).size() != maxU128 {
		t.Fatal("the size of the IPv6 space must saturate")
	}
	// Sets of different families never mix.
	v4, v6 := setOfPrefix(netip.MustParsePrefix("10.0.0.0/8")), setOfPrefix(netip.MustParsePrefix("fc00::/7"))
	if v4.overlaps(v6) || !v4.intersect(v6).empty() || !v4.subtract(v6).equal(v4) {
		t.Fatal("IPv4 and IPv6 sets must be disjoint")
	}
	if inside, outside := v4.split(netip.MustParsePrefix("::/0")); !inside.empty() || !outside.equal(v4) {
		t.Fatal("an IPv6 prefix matched IPv4 sources")
	}
}

func TestSourceScopeFollowsAddressesNotRuleShapes(t *testing.T) {
	scope := func(prefixes ...string) string {
		var parsed []netip.Prefix
		for _, p := range prefixes {
			parsed = append(parsed, netip.MustParsePrefix(p))
		}
		return string(classifySet(setOfPrefixes(parsed)))
	}
	for _, tt := range []struct {
		want     string
		prefixes []string
	}{
		{"EXPOSED", []string{"0.0.0.0/0"}},
		{"EXPOSED", []string{"::/0"}},
		{"EXPOSED", []string{"203.0.0.0/15"}},                    // more than a /16 of public addresses
		{"EXPOSED", []string{"203.0.0.0/16", "198.51.100.0/24"}}, // together more than a /16
		{"SUBNET", []string{"203.0.113.0/24"}},
		{"SUBNET", []string{"203.0.0.0/16"}},
		{"SUBNET", []string{"192.168.0.0/15"}}, // a private /16 and a public /16
		{"SUBNET", []string{"2001:db8::/48"}},
		{"EXPOSED", []string{"2001:db8::/47"}},
		{"LOCALNET", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"LOCALNET", []string{"10.0.0.0/8", "203.0.113.7/32"}}, // one public host does not make a network
		{"LOCALNET", []string{"fc00::/7", "fe80::/10"}},
		{"WHITELISTED", []string{"203.0.113.7/32"}},
		{"WHITELISTED", []string{"203.0.113.7/32", "10.1.2.3/32", "198.51.100.200/32"}},
		{"WHITELISTED", []string{"2001:db8::1/128"}},
		{"", nil},
	} {
		if got := scope(tt.prefixes...); got != tt.want {
			t.Errorf("%v: scope %q, want %q", tt.prefixes, got, tt.want)
		}
	}
}

func classifySet(sources addrSet) models.AccessScope {
	scope, _ := classifyAcceptedSources(segments(sources, nil, false))
	return scope
}
