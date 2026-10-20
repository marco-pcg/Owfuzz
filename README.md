# Owfuzz - native Go adaptation

This branch rewrites the `test/add-features` campaign architecture in Go. The default
build produces one native executable with **no cgo, external Go modules, libpcap,
libnl, or C fuzzer subprocess dependency**. The original C implementation remains under
`owfuzz/` for provenance, research comparison, and features that have not reached
behavioral parity. Nothing runs it implicitly.

## Build and test

Go 1.22 or newer is required. From the repository root:

```sh
make                         # bin/owfuzz
make test                    # hardware-free tests
make race                    # Go race detector (needs a supported host/C toolchain)
make vet
make cross                   # Linux ARM64 and ARMv7, CGO_ENABLED=0
```

The standalone build is also `CGO_ENABLED=0 go build -o bin/owfuzz ./cmd/owfuzz`.
`make legacy` explicitly builds the C reference using its original dependencies.
`make parity` optionally compares an existing C executable with the Go executable
logic. These C oracle checks are test-only; `make test` works without that binary.

## Generate reproducible captures

```sh
./bin/owfuzz --list-protocols
./bin/owfuzz --protocol ethernet --frame arp_request \
  --strategy bitflip --seed 42 --count 100 --output /tmp/arp.pcap
./bin/owfuzz --protocol 802.11 --frame all \
  --strategy bitflip --seed 42 --count 41 --output /tmp/wifi.pcap
./bin/owfuzz --protocol 802.11be --frame ml_probe_response \
  --strategy truncate --seed 42 --count 100 --output /tmp/ml.pcap
./bin/owfuzz --frame beacon --strategy ie --count 2048 --output /tmp/ies.pcap
```

Families/profiles are `802.11`, `ethernet`, `802.11be`, `p2p`, `awdl`, and `mesh`.
The 42 legacy WiFi names/IDs are retained, including the explicitly unsupported
`control_frame_extension` stub. `--frame all` skips that stub; an explicit selection
fails. Other frame builders are reimplemented as deterministic Go wire templates,
not copies of C's global, libc-random, per-frame mutation machines. See the
[compatibility matrix](docs/go-port.md) before comparing campaigns.

Strategies are `none`, `bitflip`, `truncate`, `bytes`, management-only `ie`, and
P2P/WPS/AWDL `attributes`.
`none` preserves the selected constructor's bytes; it does not certify protocol
conformance. Structured IE controls include repeated `--ie ID:HEX` and
`--ie-mode append|replace|omit|duplicate|invalid-length`. Multi-Link remains an element-level corpus. P2P public actions, AWDL vendor
actions, and mesh discovery/peering also have packet-driven responders; they do not
claim complete group formation, synchronization, or vendor-specific interoperability.

## Replay and interactive execution

```sh
./bin/owfuzz --mode replay --input /tmp/wifi.pcap --output /tmp/replay.pcap
./bin/owfuzz --mode replay --input old-fuzzing_pkts.txt \
  --input-format hex --output /tmp/old-poc.pcap
./bin/owfuzz --mode interactive --role ap --input requests.pcap \
  --output /tmp/responses.pcap --log /tmp/session.jsonl
./bin/owfuzz --mode combined --role ap --input requests.pcap \
  --frame beacon --strategy bitflip --output /tmp/combined.pcap
```

Replay emits synthetic timestamps based on record order; it does not preserve original
capture timing. Use `--interval` to set send pacing.

Input auto-detection handles classic PCAP (including big-endian/nanosecond files),
legacy `\xHH` hex logs, and Go JSONL send-event logs. Radiotap captures are stripped
and their FCS flags checked. PCAPNG is not supported. Replay and interactive modes
read to EOF by default; `--count N` limits input frames. Campaigns default to one
packet and require a positive count. Binary PCAP goes to stdout unless `--output`
is set; diagnostic packet logs go to the separate `--log` path.

The packet-driven AP/STA controllers implement OPEN association and a WPA2-PSK
CCMP four-way exchange with MIC, replay-counter, and wrapped-key checks. Select
`--auth WPA2_PSK_AES --password ...` for that controller. The implementation uses
deterministic nonces to reproduce fuzzing sessions, not cryptographic randomness
for a production access point. It does not install CCMP data keys, implement a
secure network service, or negotiate SAE, TKIP, WEP, or enterprise EAP. Unsupported
strict authentication fails before output creation. For the original fuzzer-style
malformed exchanges, explicitly select `--exchange fuzz`: SAE commit/confirm, WEP
challenge, WPA/TKIP key messages, and EAP identity/method responses then use bounded,
deterministic fuzz data and report `fuzzing-exchange`, never a verified connection.

Example profile and malformed-authentication runs:

```sh
./bin/owfuzz --protocol p2p --mode interactive --input p2p.pcap \
  --strategy attributes --output /tmp/p2p-replies.pcap
./bin/owfuzz --mode interactive --exchange fuzz --auth WPA3 \
  --input sae.pcap --output /tmp/sae-fuzz.pcap
```

Strict mode validates an OPEN/WPA2 exchange; fuzz mode tests malformed authentication
responses and does not validate a secure handshake. WPA3 remains unsupported in
strict mode. No TLS/EAP authentication service or SAE password implementation is implied.

## Linux live interfaces

Live I/O is explicit and requires appropriate raw-socket permissions and an already
configured monitor interface for WiFi. Go uses AF_PACKET directly, checks the
interface link type, and uses `iw` only when a channel is requested. It does not
create monitor interfaces, launch hostapd, or change MAC addresses.

```sh
sudo ./bin/owfuzz --frame beacon --count 100 --interval 100ms \
  --interface mon0 --channel 6 --timeout 20s --log /tmp/sent.jsonl
sudo ./bin/owfuzz --mode interactive --role sta --ssid lab \
  --source 02:00:00:00:00:02 --bssid 02:00:00:00:00:01 \
  --destination 02:00:00:00:00:01 --interface mon0 --channel 6 --timeout 30s
```

Campaigns support comma-separated interfaces/channels. Interactive sessions use
one interface/channel. Live AP sessions emit periodic beacons. `--mode mitm`
provides bounded two-interface forwarding, not the old external rogue-AP topology.
`--target-ip`/`-I` optionally enables IPv4 ICMP reachability checks. No radio or
embedded board was exercised during this port; capture/controller tests use
synthetic packets. Cross-compilation establishes buildability, not board behavior.

Legacy short-option aliases and the supported INI configuration sections are
accepted with `--config PATH`; explicit CLI flags override configuration values.
Configuration is never loaded implicitly. JSON progress from `--state` is diagnostic
and contains no handshake keys; it is not a restart/resume checkpoint.

## Extending the Go system

Add a Go file to `modules/` with a family provider, or register a family in a caller's
`protocol.Registry`. Go automatically includes source files in that package:

```go
package modules

import "owfuzz/protocol"

func init() {
    provide(func() protocol.Family {
        return protocol.Family{Name: "example", LinkType: 147, Frames: []protocol.Frame{
            {ID: 65536, Name: "example", Build: func(*protocol.Context) (protocol.Packet, error) {
                return protocol.Packet{Data: []byte{42}, LinkType: 147}, nil
            }},
        }}
    })
}
```

A test adds and removes a previously unknown family in an isolated source copy,
rebuilds with the normal Go command, and exercises the new frame without changing
core files or build lists. Builders, mutators, transports, receivers, and controllers
are independent contracts. Context/RNG state belongs to one campaign.

## Developer-effort measurements

The recorder is also implemented in Go, using `owfuzz study start|finish|report`.
See [the Go adaptation guide](docs/go-port.md#developer-effort-recorder). It records
observations and paired comparisons; it does not invent developer-time savings.

The original project is Copyright (C) 2020-2021 Hongjian Cao and contributors.
This adaptation retains GPL-3.0-or-later licensing; bundled C components retain their
original individual licenses. [Historical C documentation](docs/legacy-c-README.md)
and [the C-branch architecture](docs/protocol-extension.md) remain reference material.
