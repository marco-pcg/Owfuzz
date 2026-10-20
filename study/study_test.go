package study

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	records := []Record{{Variant: "baseline", Participant: "p1", Task: "frame", Trial: 1, Seconds: 120}, {Variant: "refactored", Participant: "p1", Task: "frame", Trial: 1, Seconds: 30}, {Variant: "baseline", Participant: "p1", Task: "frame", Trial: 2, Seconds: 90}}
	r, e := Compare(records)
	if e != nil || r.Pairs[0].Reduction != 75 || r.Unpaired != 1 || r.Groups["baseline"].MedianSeconds != 105 {
		t.Fatal(e, r)
	}
	if _, e = Compare(append(records, records[0])); e == nil {
		t.Fatal("duplicate admitted")
	}
	empty, e := Compare(nil)
	if e != nil || len(empty.Pairs) != 0 {
		t.Fatal(e)
	}
}
func TestRecorderInIsolatedFixture(t *testing.T) {
	if _, _, e := uptime(); e != nil {
		t.Skip("Linux effort timer")
	}
	root := t.TempDir()
	call := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(e, string(b))
		}
	}
	call("init", "-q")
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("before\n"), 0600)
	call("add", "file.txt")
	call("-c", "user.name=Test Fixture", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
	base, e := git(context.Background(), root, "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	boot, up, _ := uptime()
	r := Record{Variant: "baseline", Participant: "p", Task: "extension", Trial: 1, Base: base, Repository: root, BootID: boot, StartUptime: up, Started: time.Now().UTC()}
	outside := t.TempDir()
	state := filepath.Join(outside, "state.json")
	results := filepath.Join(outside, "results.jsonl")
	b, _ := json.Marshal(r)
	_ = os.WriteFile(state, b, 0600)
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("before\nafter\n"), 0600)
	_ = os.WriteFile(filepath.Join(root, "new\nfile.txt"), []byte("new\n"), 0600)
	time.Sleep(20 * time.Millisecond)
	var out, stderr bytes.Buffer
	if e = Run(context.Background(), []string{"finish", "--state", state, "--results", results, "--validation", "fixture checks"}, &out, &stderr); e != nil {
		t.Fatal(e)
	}
	records, e := readRecords(results)
	if e != nil || len(records) != 1 || records[0].ChangedFiles != 2 || records[0].Added != 2 {
		t.Fatal(e, records)
	}
	if _, e = os.Stat(state); !os.IsNotExist(e) {
		t.Fatal("trial state retained")
	}
	out.Reset()
	if e = Run(context.Background(), []string{"report", "--results", results}, &out, &stderr); e != nil {
		t.Fatal(e)
	}
}
