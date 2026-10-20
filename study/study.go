// SPDX-License-Identifier: GPL-3.0-or-later
// Package study records observed developer effort; it never estimates human time.
package study

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Change struct {
	Path    string `json:"path"`
	Added   *int   `json:"added"`
	Deleted *int   `json:"deleted"`
}
type Record struct {
	Variant      string    `json:"variant"`
	Task         string    `json:"task"`
	Participant  string    `json:"participant"`
	Trial        int       `json:"trial"`
	Base         string    `json:"base"`
	Repository   string    `json:"repository"`
	Started      time.Time `json:"started_at"`
	Finished     time.Time `json:"finished_at,omitempty"`
	BootID       string    `json:"boot_id,omitempty"`
	StartUptime  float64   `json:"start_uptime,omitempty"`
	Seconds      float64   `json:"seconds"`
	Validation   string    `json:"validation"`
	ChangedFiles int       `json:"changed_files"`
	CoreFiles    int       `json:"core_files_changed"`
	Added        int       `json:"added_lines"`
	Deleted      int       `json:"deleted_lines"`
	Changes      []Change  `json:"changes"`
}

func git(ctx context.Context, root string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = root
	b, e := cmd.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), e, b)
	}
	return strings.TrimSpace(string(b)), nil
}
func inside(path, root string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && (rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
func uptime() (string, float64, error) {
	id, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", 0, e
	}
	raw, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return "", 0, e
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return "", 0, errors.New("empty uptime")
	}
	n, e := strconv.ParseFloat(fields[0], 64)
	return strings.TrimSpace(string(id)), n, e
}
func median(v []float64) float64 {
	sort.Float64s(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

type Summary struct {
	Observations    int     `json:"observations"`
	MedianSeconds   float64 `json:"median_seconds"`
	MedianCoreFiles float64 `json:"median_core_files_changed"`
}
type Pair struct {
	Participant string  `json:"participant"`
	Task        string  `json:"task"`
	Trial       int     `json:"trial"`
	Baseline    float64 `json:"baseline_seconds"`
	Refactored  float64 `json:"refactored_seconds"`
	Reduction   float64 `json:"time_reduction_percent"`
}
type Report struct {
	Groups   map[string]Summary `json:"groups"`
	Pairs    []Pair             `json:"paired_comparisons"`
	Unpaired int                `json:"unpaired_observations"`
}

func Compare(records []Record) (Report, error) {
	out := Report{Groups: map[string]Summary{}, Pairs: []Pair{}}
	groups := map[string][]Record{}
	pairs := map[string]map[string]Record{}
	for _, r := range records {
		if (r.Variant != "baseline" && r.Variant != "refactored") || r.Seconds <= 0 || math.IsNaN(r.Seconds) || math.IsInf(r.Seconds, 0) || r.Participant == "" || r.Task == "" || r.Trial < 1 {
			return out, errors.New("invalid observation")
		}
		key := fmt.Sprintf("%q/%q/%d", r.Participant, r.Task, r.Trial)
		if pairs[key] == nil {
			pairs[key] = map[string]Record{}
		}
		if _, exists := pairs[key][r.Variant]; exists {
			return out, errors.New("duplicate observation")
		}
		pairs[key][r.Variant] = r
		groups[r.Variant] = append(groups[r.Variant], r)
	}
	for variant, rows := range groups {
		var seconds, cores []float64
		for _, r := range rows {
			seconds = append(seconds, r.Seconds)
			cores = append(cores, float64(r.CoreFiles))
		}
		out.Groups[variant] = Summary{len(rows), median(seconds), median(cores)}
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		values := pairs[k]
		before, b := values["baseline"]
		after, a := values["refactored"]
		if !a || !b {
			out.Unpaired += len(values)
			continue
		}
		out.Pairs = append(out.Pairs, Pair{before.Participant, before.Task, before.Trial, before.Seconds, after.Seconds, (before.Seconds - after.Seconds) / before.Seconds * 100})
	}
	return out, nil
}

var core = map[string]bool{"protocol/protocol.go": true, "internal/app/app.go": true, "internal/app/config.go": true, "cmd/owfuzz/main.go": true, "Makefile": true, "go.mod": true, "owfuzz/src/fuzz_control.c": true, "owfuzz/src/frames/frame.c": true, "owfuzz/src/frames/frame.h": true, "owfuzz/src/common/config.c": true, "owfuzz/src/Makefile": true, "owfuzz/Makefile": true}

func measure(ctx context.Context, r *Record) error {
	cmd := exec.CommandContext(ctx, "git", "diff", "--numstat", "-z", r.Base, "--")
	cmd.Dir = r.Repository
	b, e := cmd.Output()
	if e != nil {
		return e
	}
	fields := bytes.Split(b, []byte{0})
	for i := 0; i < len(fields); i++ {
		if len(fields[i]) == 0 {
			continue
		}
		parts := bytes.SplitN(fields[i], []byte{'\t'}, 3)
		if len(parts) != 3 {
			return errors.New("malformed numstat")
		}
		path := string(parts[2])
		if path == "" {
			if i+2 >= len(fields) {
				return errors.New("short rename")
			}
			i += 2
			path = string(fields[i])
		}
		change := Change{Path: path}
		if string(parts[0]) != "-" {
			n, e := strconv.Atoi(string(parts[0]))
			if e != nil {
				return e
			}
			change.Added = &n
		}
		if string(parts[1]) != "-" {
			n, e := strconv.Atoi(string(parts[1]))
			if e != nil {
				return e
			}
			change.Deleted = &n
		}
		r.Changes = append(r.Changes, change)
	}
	cmd = exec.CommandContext(ctx, "git", "ls-files", "--others", "--exclude-standard", "-z")
	cmd.Dir = r.Repository
	b, e = cmd.Output()
	if e != nil {
		return e
	}
	for _, raw := range bytes.Split(b, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		path := string(raw)
		b, e = os.ReadFile(filepath.Join(r.Repository, path))
		if e != nil {
			return e
		}
		n := bytes.Count(b, []byte{'\n'})
		if len(b) > 0 && b[len(b)-1] != '\n' {
			n++
		}
		zero := 0
		r.Changes = append(r.Changes, Change{path, &n, &zero})
	}
	r.ChangedFiles = len(r.Changes)
	for _, c := range r.Changes {
		if core[c.Path] {
			r.CoreFiles++
		}
		if c.Added != nil {
			r.Added += *c.Added
		}
		if c.Deleted != nil {
			r.Deleted += *c.Deleted
		}
	}
	return nil
}
func Run(ctx context.Context, args []string, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("study start|finish|report required")
	}
	f := flag.NewFlagSet("study "+args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	var state, results, variant, task, participant, base, validation string
	var trial int
	f.StringVar(&state, "state", "", "state JSON")
	f.StringVar(&results, "results", "", "observations JSONL")
	f.StringVar(&variant, "variant", "", "baseline/refactored")
	f.StringVar(&task, "task", "", "task identifier")
	f.StringVar(&participant, "participant", "", "participant identifier")
	f.StringVar(&base, "base", "HEAD", "base commit")
	f.StringVar(&validation, "validation", "", "checks actually run")
	f.IntVar(&trial, "trial", 1, "trial number")
	if e := f.Parse(args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected study arguments")
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	switch args[0] {
	case "start":
		if state == "" || task == "" || participant == "" || trial < 1 || (variant != "baseline" && variant != "refactored") {
			return errors.New("state, task, participant, positive trial and variant required")
		}
		root, e := git(ctx, "", "rev-parse", "--show-toplevel")
		if e != nil {
			return e
		}
		state, e = filepath.Abs(state)
		if e != nil {
			return e
		}
		if inside(state, root) {
			return errors.New("store state outside repository")
		}
		status, e := git(ctx, root, "status", "--porcelain")
		if e != nil {
			return e
		}
		if status != "" {
			return errors.New("trial must start from a clean checkout")
		}
		commit, e := git(ctx, root, "rev-parse", base+"^{commit}")
		if e != nil {
			return e
		}
		boot, up, e := uptime()
		if e != nil {
			return fmt.Errorf("effort timer requires Linux uptime: %w", e)
		}
		r := Record{Variant: variant, Task: task, Participant: participant, Trial: trial, Base: commit, Repository: root, Started: time.Now().UTC(), BootID: boot, StartUptime: up}
		file, e := os.OpenFile(state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		e = json.NewEncoder(file).Encode(r)
		ce := file.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		fmt.Fprintln(out, "Trial started.")
		return nil
	case "finish":
		if state == "" || results == "" || validation == "" {
			return errors.New("state, results and validation required")
		}
		b, e := os.ReadFile(state)
		if e != nil {
			return e
		}
		var r Record
		if e = json.Unmarshal(b, &r); e != nil {
			return e
		}
		if r.Repository == "" || r.Base == "" || r.StartUptime <= 0 || r.BootID == "" {
			return errors.New("invalid trial state")
		}
		absolute, e := filepath.Abs(results)
		if e != nil {
			return e
		}
		if inside(absolute, r.Repository) {
			return errors.New("store results outside repository")
		}
		boot, up, e := uptime()
		if e != nil {
			return e
		}
		if boot != r.BootID || up <= r.StartUptime {
			return errors.New("clock/boot changed; restart trial")
		}
		r.Seconds = up - r.StartUptime
		r.Finished = time.Now().UTC()
		r.Validation = validation
		if e = measure(ctx, &r); e != nil {
			return e
		}
		existing, e := readRecords(results)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if _, e = Compare(append(existing, r)); e != nil {
			return e
		}
		file, e := os.OpenFile(results, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if e != nil {
			return e
		}
		e = json.NewEncoder(file).Encode(r)
		ce := file.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if e = os.Remove(state); e != nil {
			return e
		}
		return encoder.Encode(r)
	case "report":
		if results == "" {
			return errors.New("--results required")
		}
		records, e := readRecords(results)
		if e != nil {
			return e
		}
		summary, e := Compare(records)
		if e != nil {
			return e
		}
		return encoder.Encode(summary)
	default:
		return errors.New("unknown study command")
	}
}
func readRecords(path string) ([]Record, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []Record
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 4*1024*1024)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var r Record
		if e = json.Unmarshal(s.Bytes(), &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, s.Err()
}
