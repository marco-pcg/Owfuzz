Source and evidence for Marco Lira's Owfuzz research manuscript

Manuscript: English, six-page two-column research draft.
Author: Marco Lira, CEFET/RJ.
Baseline: 10af304; evaluated branch commit: e98b03e.

The editable Markdown contains the complete paper, tables and diagram text.
The JSON preserves raw function/file observations for the defined production-C scope.

To reproduce static metrics, use a checkout containing both commits. Install
Lizard 1.24.1, then run measure_branch.py from the repository root. It writes
output/pdf/owfuzz-branch-metrics.json. This script is not the participant timer.
The branch's tools/extension_metrics.py provides that separate future-study recorder.

Validation logs were collected 20 October 2026. Integrated checks reused
up-to-date build products and were offline; no radio or board tests were run.
The protocol core also passed AddressSanitizer/UndefinedBehaviorSanitizer with
ASAN_OPTIONS=detect_leaks=0. Environment: x86-64 Linux; GCC 15.2.0; Python 3.14.4.

No participant-time savings or complete 802.11be MLO implementation is claimed.
The reference manuscript is credited to its original authors in reference [2];
its experimental outcomes have not been relabeled as this project's outcomes.
