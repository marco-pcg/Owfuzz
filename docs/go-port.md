# Go adaptation: architecture, compatibility and validation

The Go branch starts at C commit `e98b03e` on `test/add-features`. The root Go module
and Makefile are the active implementation. The C tree is retained unchanged as a
research reference and optional test oracle. The Go executable never invokes it,
links it, or depends on Python registration/measurement tools.

## Package boundaries

| Package | Responsibility |
| --- | --- |
| `protocol` | Registry, descriptor factories, campaign-local RNG, mutation, bounded packets, transport contracts |
| `modules` | Native Ethernet and Multi-Link cases, 42 WiFi entries, IE/vendor-attribute mutation, P2P/AWDL/mesh corpora |
| `wifi` | Header/DS-address parsing, TLV parsing, packet and security-advertisement serialization |
| `capture` | Classic PCAP, radiotap/FCS, legacy hex PoCs, Go JSONL replay |
| `radio` | Linux AF_PACKET send/receive, explicit channel configuration, interface groups |
| `session` | OPEN/WPA2-CCMP state machines, malformed-authentication and vendor responders, replay, forwarding, ICMP reachability |
| `study` | Effort observation recorder and paired reporting |
| `internal/app` | CLI, configuration, file ownership, composition and errors |
| `cmd/owfuzz` | Signal-aware executable entry point |

Go callback functions/interfaces retain the factory/strategy design. Registration
uses immutable copied descriptors and a mutex-protected registry. Built-in module
providers register during ordinary Go package initialization; each caller receives
a fresh registry. No C startup attribute, generated source list, cgo or dynamic loader
is required. Additions are compiled into the binary; they are not runtime plugins.

Packets are bounded at 4096 bytes and copied before mutation. A callback still has
responsibility for returning valid representations: memory-safe slices do not make
an arbitrary protocol encoding correct. Registry/transport checks enforce ownership,
nonempty data, namespaced frame identity and link compatibility. The PRNG and synthetic
capture timestamps deliberately match the C campaign engine for native corpus cases.
The PRNG is not suitable for secrets.

## Compatibility matrix

| Feature | Native Go behavior | Limits / relation to C |
| --- | --- | --- |
| Protocol registry / mutation / PCAP campaign | Implemented | Native strategy ordering and uint32 RNG retained |
| Ethernet ARP and both Multi-Link cases | Implemented | Full PCAP equality checked against C with three strategies/three seeds |
| Legacy 42 frame names and IDs | Implemented | 41 native templates; existing empty control-frame-extension stub fails explicitly |
| Original per-frame mutation sequences | Replaced by Go baseline templates plus independent/IE strategies | Not bit-for-bit parity with C's libc-random/global progression |
| WiFi management/control/data serialization | Implemented | Wire headers/addresses and bounds tested; no standards conformance certification |
| IE fuzzing | 256 IDs and extension IDs, omit/empty/value/boundary/length variants | Different sequence from C; explicit custom elements and disabled-ID maps supported |
| OPEN AP/STA association | Implemented | Synthetic full exchange tested; radio behavior unverified |
| WPA2 PSK/CCMP four-way exchange | Implemented | PBKDF2, PTK, MIC, replay counters, AES key wrap; no encrypted data service/key installation |
| WEP/WPA/TKIP/enterprise/SAE | Advertisements plus explicit `--exchange fuzz` malformed-message responders | No verified secure negotiation, TLS/EAP service or SAE password implementation; strict mode rejects these |
| P2P/AWDL/mesh | Native corpus builders, bounded vendor TLVs, public-action/AWDL/mesh responders | Full group formation, synchronization and vendor-specific behavior are not certified; templates differ from C |
| Capture replay / PoC replay | Implemented | Classic PCAP, radiotap, hex lines and JSONL; PCAPNG unsupported |
| Two-interface forwarding | Implemented | No rogue-AP/hostapd orchestration or address/key rewriting |
| Multichannel | Campaign interface groups | Interactive state belongs to a single interface/channel |
| Target reachability | Optional raw IPv4 ICMP | Requires CAP_NET_RAW and a routed IPv4 target; not a vulnerability oracle |
| Logging / progress | JSONL packet events and key-free progress | No exact legacy text-log format or handshake resume |
| Developer-effort recorder | Go start/finish/report | Linux boot/uptime timer; published core-file scope includes Go and C control paths |
| C build | Explicit `make legacy` | Not part of ordinary Go builds or default unit tests |

This is a substantive native rewrite, but **not complete behavioral parity with every
specialized legacy procedure**. In particular, a list of all original frame names
must not be interpreted as proof that every C mutation state, byte sequence or
vendor-specific interaction has an equivalent Go test. Malformed-message responders
exercise the old fuzzing roles without pretending to implement verified SAE/TLS/WEP
security services. The retained C source preserves access to those experiments
while remaining outside the Go execution path. The compatibility gaps above need
additional implementation and hardware validation before replacing those workflows.

## CLI and configuration semantics

`--protocol`, `--frame`, `--strategy`, `--count`, `--seed`, MAC and output options
retain the C campaign meanings. Legacy aliases map to the native Go options; `-T`
selects 0=replay, 1=interactive, 2=campaign, 3=combined. Unlike the C snapshot's
unimplemented combined mode, Go can interleave a configured generated frame after
each interactive response and includes those packets in its logs/progress.

`--input-format auto|pcap|hex|jsonl` controls replay input. Auto-detection recognizes
classic PCAP magic, JSON event lines beginning with `{`, and otherwise hex logs.
For leading whitespace before JSON, choose `jsonl` explicitly. JSON replay skips
receive events and replays recorded sent bytes. Original `\xHH` lines need no editing.
Input/output/log/state aliases and hardlinks are rejected to avoid clobbering input.

Supported INI sections are `[interfaces]`, `[fuzzing_option]`, `[ap-frames]`,
`[sta-frames]`, `[ies-status]`, `[ext-ies-status]` and `[mitm]`. Supported general
keys map to flags, frame flags select by name, and IE masks suppress disabled IDs.
Legacy nonempty external rogue-AP topology settings are not automatically started.
Legacy `fuzz_mode=p2p|awdl|mesh` and `-m` equivalents select the corresponding
profile. `--protocol PROFILE --mode interactive` selects its responder. Other unknown
roles fail explicitly; external rogue-AP topology settings do not launch services.

An example offline configuration:

```ini
[fuzzing_option]
fuzz_mode=ap
ssid=lab
auth_type=OPEN_NONE
test_type=2
seed=42
[ap-frames]
beacon=1
probe_response=1
[ies-status]
37=0
60=0
```

Run with `bin/owfuzz --config lab.cfg --count 100 --output /tmp/lab.pcap`.
Explicit flags are parsed after translated configuration options and take precedence.
The legacy config file is not loaded just because it is next to the executable.

## Developer-effort recorder

Use clean baseline/refactored checkouts and put observation files outside the project.
The same Go executable can measure a C baseline checkout: run it by absolute path
from that checkout. A clean starting worktree is mandatory. Generated manuscripts
under untracked `output/` must not be mixed into an extension trial.

```sh
/path/to/bin/owfuzz study start --variant refactored --task new-family \
  --participant p1 --trial 1 --state /tmp/owfuzz-trial.json
# Implement and validate the assigned extension.
/path/to/bin/owfuzz study finish --state /tmp/owfuzz-trial.json \
  --results /tmp/owfuzz-study.jsonl --validation 'acceptance checks passed'
/path/to/bin/owfuzz study report --results /tmp/owfuzz-study.jsonl
```

The Linux boot identifier and uptime measure elapsed time across separate commands
and reject a reboot. Pairing uses participant/task/trial; duplicate observations fail.
Results include changed tracked/untracked files, added/deleted lines, and core-file
edits. Tests use synthetic observations and an isolated Git fixture; no participant
study or measured productivity improvement is asserted.

## Validation and reproducibility

- `go test ./...`: registry ownership/concurrency, frame headers, all supported
  constructors, IE bounds/variants, PCAP endianness and timestamps, radiotap/FCS,
  CLI and file protection, replay, OPEN/WPA2 session transitions, MIC/replay rejection,
  packet cancellation, profile/SAE/WEP/EAP fuzz exchanges, and recorder comparisons.
- A temporary-source integration test builds and runs a newly added Go module and
  then removes it, without changing orchestration or build lists.
- An RFC 3394 AES-wrap vector and a known WPA PSK derivation vector check the crypto
  primitives independently of the two-controller synthetic exchange.
- `make parity`: 36 C/Go campaign pairs, 257 packets each, for Ethernet, both Multi-Link
  cases and ACK. Exact matching covers 9,252 record pairs; it does not cover the other
  legacy algorithms or live behavior.
- `go test -race ./...` and `go vet ./...`: host-side concurrency/static checks.
- Fuzz entry points exercise PCAP/radiotap/WiFi/TLV/EAPOL parsers; they can be run with
  `go test -fuzz=FuzzPCAP -fuzztime=10s ./capture` (one target per invocation).
- `make cross` builds Linux ARM64/ARMv7 without cgo; the portable offline code also
  builds for non-Linux targets, whose live backend returns an unsupported error.

Live radio, ICMP probing and two-interface forwarding are not exercised by automated
tests. No target device is contacted during port verification. Raw sockets, interface
capabilities, kernel radiotap handling, ACK timing and actual OpenWiFi board behavior
require a separate lab test. Go runtime/binary size and scheduling differ from C;
there is no hard real-time, lower-memory or throughput claim.

### Primary implementation references

- Existing C source at `e98b03e` and the preceding upstream code (copyright retained).
- [Hostapd WPA key definitions](https://w1.fi/wpa_supplicant/devel/wpa__common_8h_source.html).
- [RFC 3394: AES Key Wrap](https://www.rfc-editor.org/rfc/rfc3394.html).
- [Go syscall interface](https://pkg.go.dev/syscall#SockaddrLinklayer).

All new implementation source is GPL-3.0-or-later. Historical paper artifacts refer
to the C commit and have not been rewritten to claim results for the Go port.

## Authentication exchange modes

`--exchange strict` is the default for the ordinary 802.11 controller. OPEN validates
request/response sequence and WPA2-CCMP additionally validates MICs, counters and key
wrap. Deterministic fuzzing nonces are not suitable for an access-point service.

`--exchange fuzz` preserves the legacy malformed-message role: SAE commit/confirm
fields, shared-WEP challenges, WPA/WPA2/TKIP key messages and EAP responses are generated
as test inputs. These exchanges never set the controller to `connected`, never install
keys and never assert that a peer has authenticated. Only the bounds are trusted;
fields are deliberately malformed and can be mutated further by the selected strategy.
This distinction is visible in JSON state and logs, not hidden behind an OPEN fallback.

Vendor `attributes` mutation understands P2P (1-byte IDs/LE lengths), WPS (2-byte IDs/BE
lengths), and AWDL (1-byte IDs/LE lengths). It exercises omissions, empty values, boundary
payloads and inconsistent declared lengths while keeping actual buffers bounded.

### Verification performed for this working tree

The host unit suite, race detector, `go vet`, optional C oracle comparison, ARM64/ARMv7
cross-builds and 32-bit core tests passed. Short fuzz runs completed over 800,000
combined parser executions across PCAP, radiotap, WiFi and EAPOL inputs.
A subsequent corpus run found a malformed-management/DS-flags bounds panic; the
parser now rejects that header combination and the minimized case is retained in
`wifi/testdata/fuzz/FuzzParse/` as a regression test. These are bounded smoke campaigns, not exhaustive proofs of memory/protocol
correctness or performance benchmarks. CLI smoke tests generated all 41 supported WiFi
entries, replayed them byte-for-byte, and exercised P2P replies and AWDL attribute cases.
