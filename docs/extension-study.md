# Extension-effort evaluation protocol

The purpose is to compare observed time and code changes for adding a frame and
adding a protocol family, before and after this architectural change. No human
extension-time measurements have been collected yet; do not substitute runtime
packet-generation benchmarks for developer effort.

## Study design

Use a baseline checkout at the pre-refactor revision (`10af304` in this repository)
and the reviewed refactored revision. Keep study observations outside both checkouts.
Start each trial with a clean checkout and installed dependencies. Record participant,
task, trial, variant, exact starting commit, and the validation performed.

Tasks should have identical acceptance criteria across variants:

1. Add a specified frame with fixed expected bytes, selection by name, and a test.
2. Add a non-WiFi family with a bounded builder and PCAP output using its linktype.
3. Optionally add a received-packet-dependent case to assess stateful extensibility.

Use at least three repetitions per task and participant. Counterbalance variant order
across participants to reduce practice effects. Predefine whether documentation and
test-writing time are included; the recommended interval starts at reading the task
and ends when all acceptance checks pass. Record interruptions separately and apply
one exclusion policy consistently. Do not reboot or suspend across a timed trial.
The baseline may not support a task at all: record it as incomplete with a predefined
time limit, rather than reporting zero effort or inventing a successful result.

## Recording

Run in the relevant clean checkout. The script uses monotonic elapsed wall time and
records added/deleted lines, changed files (including untracked additions), and edits
to a published set of orchestration/core files. Files are counted, not semantic edits
or cyclomatic complexity. Ensure only task changes are present; compiled artifacts
must be ignored. The initial architectural refactor itself is not an extension trial.

```sh
python3 tools/extension_metrics.py start --variant refactored \
  --task new-family --participant p1 --trial 1 \
  --state /tmp/owfuzz-trial.json
# Implement the assigned extension and run its acceptance checks.
python3 tools/extension_metrics.py finish --state /tmp/owfuzz-trial.json \
  --results /tmp/owfuzz-study.jsonl --validation 'protocol tests passed; corpus verified'
python3 tools/extension_metrics.py report /tmp/owfuzz-study.jsonl
```

The same recorder must be available for baseline trials: run its absolute path from
the baseline checkout. Use a separate state file for each active trial. Never reuse
a participant/task/trial/variant key; the report rejects duplicates. Keep detailed
acceptance criteria and failed/incomplete trials in the study notebook alongside the
JSONL results. Only completed observations should enter the paired time comparison.

The report provides per-variant medians and pairs observations by participant, task,
and trial. Time reduction is `(baseline_seconds - refactored_seconds) /
baseline_seconds * 100`. Negative values mean the refactored trial took longer.
Unpaired observations are reported, not silently paired with unrelated trials.
Report dispersion, sample size, training, environment, incomplete trials, and learning
bias in the final paper. The script intentionally does not claim statistical
significance or establish market novelty.

## Expected architectural evidence

The protocol extension integration test demonstrates adding a family by adding its
module alone. It supports the claim that the new campaign engine needs zero core
edits for a new module. It does not establish a measured improvement in developer
time, eliminate regression testing, or establish that the framework is the first of
its kind. Those claims require the empirical study and a separate literature review.
