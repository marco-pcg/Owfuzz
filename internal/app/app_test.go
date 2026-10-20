package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"owfuzz/capture"
	"owfuzz/modules"
	"owfuzz/protocol"
)

func run(t *testing.T, args ...string) []byte {
	t.Helper()
	var out, err bytes.Buffer
	if e := Run(context.Background(), args, &out, &err); e != nil {
		t.Fatalf("%v: %v %s", args, e, err.String())
	}
	return out.Bytes()
}
func TestCLICampaignAndValidation(t *testing.T) {
	args := []string{"--protocol", "ethernet", "--frame", "arp_request", "--strategy", "bitflip", "--seed", "0", "--count", "5"}
	a := run(t, args...)
	b := run(t, args...)
	if !bytes.Equal(a, b) {
		t.Fatal("campaign not reproducible")
	}
	reader, e := capture.NewReader(bytes.NewReader(a))
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e = reader.Receive(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range [][]string{{"--seed", "-1"}, {"--seed", "4294967296"}, {"--count", "0"}, {"--source", "bad"}, {"--strategy", "missing"}, {"--frame", "control_frame_extension"}, {"--mode", "interactive", "--auth", "WPA3", "--input", "missing.pcap"}, {"--mode", "replay"}, {"--mode", "unknown"}, {"--channel", "-1"}, {"--payload", "zz"}, {"--count", "1000001"}} {
		var out, err bytes.Buffer
		if e = Run(context.Background(), bad, &out, &err); e == nil {
			t.Fatalf("accepted %v", bad)
		}
		if out.Len() != 0 {
			t.Fatalf("partial output before validation %v", bad)
		}
	}
	listing := string(run(t, "--list-protocols"))
	for _, name := range []string{"802.11 (", "802.11be (", "ethernet (", "awdl (", "mesh (", "p2p ("} {
		if !strings.Contains(listing, name) {
			t.Fatal(name)
		}
	}
}
func TestReplayFilesLoggingAndInputProtection(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcap")
	output := filepath.Join(dir, "output.pcap")
	log := filepath.Join(dir, "log.jsonl")
	source := run(t, "--protocol", "ethernet", "--frame", "arp_request", "--count", "3")
	if e := os.WriteFile(input, source, 0600); e != nil {
		t.Fatal(e)
	}
	run(t, "--protocol", "ethernet", "--mode", "replay", "--input", input, "--output", output, "--log", log)
	got, e := os.ReadFile(output)
	if e != nil || !bytes.Equal(source, got) {
		t.Fatal(e, "replay differs")
	}
	events, _ := os.ReadFile(log)
	if len(bytes.Split(bytes.TrimSpace(events), []byte{'\n'})) != 3 {
		t.Fatal("log count")
	}
	var out, err bytes.Buffer
	if e = Run(context.Background(), []string{"--protocol", "ethernet", "--mode", "replay", "--input", input, "--output", input}, &out, &err); e == nil {
		t.Fatal("clobbered input")
	}
	got, _ = os.ReadFile(input)
	if !bytes.Equal(source, got) {
		t.Fatal("input changed")
	}
	alias := filepath.Join(dir, "alias")
	if e = os.Link(input, alias); e != nil {
		t.Fatal(e)
	}
	if e = Run(context.Background(), []string{"--protocol", "ethernet", "--mode", "replay", "--input", input, "--output", alias}, &out, &err); e == nil {
		t.Fatal("hardlink accepted")
	}
}
func TestInteractivePCAPAndConfig(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "requests.pcap")
	output := filepath.Join(dir, "responses.pcap")
	r, _ := modules.NewRegistry()
	f, _ := r.Family("802.11")
	none, _ := protocol.Strategy("none")
	c := protocol.DefaultContext()
	c.Role = "sta"
	c.Source = protocol.MAC{2, 0, 0, 0, 0, 2}
	c.Destination = c.BSSID
	var captureBytes bytes.Buffer
	writer, _ := capture.NewWriter(&captureBytes, protocol.WiFi)
	for i, name := range []string{"probe_request", "authentication", "association_request"} {
		c.Iteration = uint64(i)
		p, e := protocol.Generate(f, name, &c, none)
		if e != nil {
			t.Fatal(e)
		}
		_ = writer.Send(context.Background(), p)
	}
	_ = os.WriteFile(input, captureBytes.Bytes(), 0600)
	run(t, "--mode", "interactive", "--input", input, "--output", output, "--state", filepath.Join(dir, "progress.json"))
	data, e := os.ReadFile(filepath.Join(dir, "progress.json"))
	if e != nil {
		t.Fatal(e)
	}
	var state struct {
		State string `json:"state"`
		Sent  uint64 `json:"sent"`
	}
	if e = json.Unmarshal(data, &state); e != nil || state.State != "connected" || state.Sent != 4 {
		t.Fatal(e, string(data))
	}
	cfg := filepath.Join(dir, "config.cfg")
	_ = os.WriteFile(cfg, []byte("[fuzzing_option]\nfuzz_mode=sta\nssid=configured\nseed=5\ntest_type=2\n[sta-frames]\nprobe_request=1\n"), 0600)
	a := run(t, "--config", cfg, "--ssid", "override")
	if !bytes.Contains(a, []byte("override")) || bytes.Contains(a, []byte("configured")) {
		t.Fatal("explicit flag precedence")
	}
	_ = os.WriteFile(cfg, []byte("[ap-frames]\ninvalid=1\n"), 0600)
	var out, err bytes.Buffer
	if e = Run(context.Background(), []string{"--config", cfg}, &out, &err); e == nil {
		t.Fatal("unknown config frame accepted")
	}
}
func TestCNativeDifferential(t *testing.T) {
	reference := os.Getenv("OWFUZZ_C_REFERENCE")
	if reference == "" {
		t.Skip("set OWFUZZ_C_REFERENCE to the C executable for optional cross-language checks")
	}
	for _, f := range []struct{ family, frame string }{{"ethernet", "arp_request"}, {"802.11be", "ml_probe_response"}, {"802.11be", "ml_invalid_common_length"}, {"802.11", "ack"}} {
		for _, strategy := range []string{"none", "bitflip", "truncate"} {
			for _, seed := range []string{"0", "1", "4294967295"} {
				args := []string{"--protocol", f.family, "--frame", f.frame, "--strategy", strategy, "--seed", seed, "--count", "257"}
				want, e := exec.Command(reference, args...).Output()
				if e != nil {
					t.Fatal(e)
				}
				got := run(t, args...)
				if !bytes.Equal(want, got) {
					t.Fatalf("%s/%s %s seed %s mismatch", f.family, f.frame, strategy, seed)
				}
			}
		}
	}
	fmt.Fprintln(os.Stderr, "C/Go differential: 36 campaign pairs (257 records each) matched byte-for-byte")
}
func TestDropInGoModuleWithoutCoreEdits(t *testing.T) {
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Clean(filepath.Join(cwd, "../.."))
	fixture := t.TempDir()
	for _, dir := range []string{"cmd", "protocol", "modules", "capture", "radio", "session", "internal", "study", "wifi"} {
		e = filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			destination := filepath.Join(fixture, rel)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0700)
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				b, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				return os.WriteFile(destination, b, 0600)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "go.mod"))
	if e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(filepath.Join(fixture, "go.mod"), b, 0600)
	module := `package modules
import "owfuzz/protocol"
func init(){provide(func()protocol.Family{return protocol.Family{Name:"fixture",LinkType:147,Frames:[]protocol.Frame{{ID:65536,Name:"new_frame",Build:func(*protocol.Context)(protocol.Packet,error){return protocol.Packet{Data:[]byte{42},LinkType:147},nil}}}}})}
`
	extension := filepath.Join(fixture, "modules/fixture.go")
	if e = os.WriteFile(extension, []byte(module), 0600); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(t.TempDir(), "owfuzz")
	build := func() {
		t.Helper()
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "./cmd/owfuzz")
		cmd.Dir = fixture
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(e, string(b))
		}
	}
	build()
	out, e := exec.Command(binary, "--protocol", "fixture", "--frame", "new_frame").Output()
	if e != nil {
		t.Fatal(e)
	}
	reader, e := capture.NewReader(bytes.NewReader(out))
	if e != nil || reader.LinkType() != 147 {
		t.Fatal(e)
	}
	p, e := reader.Receive(context.Background())
	if e != nil || !bytes.Equal(p.Data, []byte{42}) {
		t.Fatal(e)
	}
	if e = os.Remove(extension); e != nil {
		t.Fatal(e)
	}
	build()
	listing, e := exec.Command(binary, "--list-protocols").Output()
	if e != nil || bytes.Contains(listing, []byte("fixture")) {
		t.Fatal(e, "removed module still registered")
	}
}
func TestConfigEmptyValuesAndDisabledFrames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	content := "[fuzzing_option]\nfuzz_mode=ap\nssid=\ntest_type=2\n[ap-frames]\nbeacon=0\n"
	_ = os.WriteFile(path, []byte(content), 0600)
	var out, stderr bytes.Buffer
	if e := Run(context.Background(), []string{"--config", path}, &out, &stderr); e == nil {
		t.Fatal("all-disabled frames silently defaulted")
	}
	run(t, "-config="+path, "--frame", "beacon")
	parsed, e := parse([]string{"--config", path, "--frame", "beacon"}, &stderr)
	if e != nil || parsed.ssid != "" {
		t.Fatal("empty configured SSID not preserved", e)
	}
}
