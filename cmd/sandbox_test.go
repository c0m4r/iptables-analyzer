package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/c0m4r/iptables-analyzer/internal/loader"
	"github.com/c0m4r/iptables-analyzer/internal/models"
	"github.com/c0m4r/iptables-analyzer/internal/sandbox"
	"github.com/c0m4r/iptables-analyzer/internal/services"
)

// cliChildEnv makes the test binary run the real command line instead of
// the tests, so that the real sandbox can be enforced in a child process.
const cliChildEnv = "IPTABLES_ANALYZER_CLI_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(cliChildEnv) != "" {
		Execute()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const liveSSOutput = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
	"LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"

// recordingDependencies log the order of input collection and sandboxing.
func recordingDependencies(t *testing.T, events *[]string, out *bytes.Buffer) commandDependencies {
	t.Helper()
	rules, err := os.ReadFile(filepath.Join("..", "testdata", "basic.iptables-save"))
	if err != nil {
		t.Fatal(err)
	}
	return commandDependencies{
		readRules: func(cfg loader.Config) (loader.Sources, error) {
			*events = append(*events, "rules")
			return loader.Sources{IPv4: &loader.Source{Version: models.IPv4, Data: string(rules)}}, nil
		},
		readServices: func(string) (string, error) {
			*events = append(*events, "services-file")
			return liveSSOutput, nil
		},
		collectServices: func() services.Capture {
			*events = append(*events, "services-live")
			return services.Capture{Outputs: []services.Output{{Proto: "tcp", Data: liveSSOutput}}}
		},
		getHost: func() (*models.HostContext, error) {
			*events = append(*events, "host")
			return &models.HostContext{Interfaces: []models.HostInterface{{Name: "lo", Up: true}}}, nil
		},
		isRoot: func() bool { return true },
		sandbox: func(mode sandbox.Mode) (models.SandboxStatus, error) {
			*events = append(*events, "sandbox:"+string(mode))
			if out.Len() != 0 {
				t.Error("output was written before the sandbox was enforced")
			}
			return models.SandboxStatus{Mode: string(mode), Landlock: true, LandlockABI: 7}, nil
		},
	}
}

func TestSandboxFollowsLiveInputCollection(t *testing.T) {
	var events []string
	var out bytes.Buffer
	command := newRootCommand(recordingDependencies(t, &events, &out))
	command.SetOut(&out)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "rules,host,services-live,sandbox:auto" {
		t.Fatalf("unexpected order of input collection and sandboxing: %s", got)
	}
	var report models.AnalysisResult
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Sandbox == nil || !report.Sandbox.Landlock || len(report.Services) != 1 {
		t.Fatalf("report lost the sandbox status or the live services: %+v %+v", report.Sandbox, report.Services)
	}
}

func TestSandboxFollowsServicesFile(t *testing.T) {
	var events []string
	var out bytes.Buffer
	command := newRootCommand(recordingDependencies(t, &events, &out))
	command.SetOut(&out)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--no-color", "--sandbox=strict", "-f", "rules.v4", "--services-file", "ss.txt"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "rules,services-file,sandbox:strict" {
		t.Fatalf("unexpected order of input collection and sandboxing: %s", got)
	}
	if !strings.Contains(out.String(), "Landlock ABI 7") {
		t.Fatalf("report does not show the sandbox: %s", out.String())
	}
}

func TestSandboxFailureIsFatal(t *testing.T) {
	var events []string
	var out bytes.Buffer
	deps := recordingDependencies(t, &events, &out)
	deps.sandbox = func(sandbox.Mode) (models.SandboxStatus, error) {
		return models.SandboxStatus{}, errors.New("sandbox could not be fully enforced")
	}
	command := newRootCommand(deps)
	command.SetOut(&out)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"-4", "--sandbox=strict"})
	if err := command.Execute(); err == nil {
		t.Fatal("a sandbox failure must stop the analysis")
	}
	if out.Len() != 0 {
		t.Fatalf("output written despite the sandbox failure: %s", out.String())
	}
}

func TestInvalidSandboxModeIsRejected(t *testing.T) {
	command := newTestCommand(&bytes.Buffer{}, false)
	command.SetArgs([]string{"--sandbox=on", "-4", "-f", filepath.Join("..", "testdata", "basic.iptables-save")})
	if err := command.Execute(); err == nil {
		t.Fatal("invalid --sandbox value was accepted")
	}
}

// runCLI runs the real command line, including the real sandbox, in a
// child process.
func runCLI(t *testing.T, args ...string) ([]byte, string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), cliChildEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, stderr.String(), err
}

func reportWithoutSandbox(t *testing.T, data []byte) (map[string]any, map[string]any) {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	status, _ := report["Sandbox"].(map[string]any)
	delete(report, "Sandbox")
	return report, status
}

func TestRealSandboxDoesNotChangeTheReport(t *testing.T) {
	args := []string{"--json",
		"--file", filepath.Join("..", "testdata", "docker29.iptables-save"),
		"--file6", filepath.Join("..", "testdata", "docker29.ip6tables-save"),
		"--services-file", filepath.Join("..", "testdata", "services.txt")}
	unconfined, stderr, err := runCLI(t, append(args, "--sandbox=off")...)
	if err != nil {
		t.Fatalf("unconfined run failed: %v\n%s", err, stderr)
	}
	want, _ := reportWithoutSandbox(t, unconfined)

	// The text renderer must also work in the sandbox.
	text, stderr, err := runCLI(t, append(args[1:], "--no-color", "--verbose")...)
	if err != nil || !strings.Contains(string(text), "Recommended Baseline") {
		t.Fatalf("text report failed in the sandbox: %v\n%s", err, stderr)
	}

	for _, mode := range []string{"auto", "strict"} {
		out, stderr, err := runCLI(t, append(args, "--sandbox="+mode)...)
		if err != nil {
			if mode == "strict" && strings.Contains(stderr, "sandbox could not be fully enforced") {
				t.Skipf("Landlock is not available here: %s", stderr)
			}
			t.Fatalf("--sandbox=%s failed: %v\n%s", mode, err, stderr)
		}
		got, status := reportWithoutSandbox(t, out)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("--sandbox=%s changed the report", mode)
		}
		if mode == "strict" && status["Landlock"] != true {
			t.Fatalf("strict mode succeeded without Landlock: %v", status)
		}
		t.Logf("--sandbox=%s: %v", mode, status)
	}
}
