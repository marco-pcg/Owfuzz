# Protocol and frame extension architecture

This branch establishes a protocol-neutral campaign engine while keeping the existing
interactive WiFi controller. Factory callbacks create frames, Strategy callbacks
mutate them and deliver them, and adapters expose the existing WiFi implementations.
These are C interfaces implemented with descriptors and function pointers, not C++ classes.

## Build and run

From the repository root:

```sh
make -C owfuzz offline
make -C owfuzz test-protocols
owfuzz/src/protocols/build/owfuzz-protocol --list-protocols
owfuzz/src/protocols/build/owfuzz-protocol --protocol ethernet --frame arp_request \
  --strategy bitflip --seed 42 --count 100 --output /tmp/arp.pcap
owfuzz/src/protocols/build/owfuzz-protocol --protocol 802.11be --frame ml_probe_response \
  --strategy truncate --seed 42 --count 100 --output /tmp/ml.pcap
```

The dependency-free executable contains Ethernet and experimental 802.11be modules.
The full `make -C owfuzz` build additionally exposes `802.11` with the 42 existing
frame entries through the same campaign API. It needs the dependencies listed in
README.md, including `libnl-genl-3-dev`. Legacy CLI invocations still enter the
existing interactive controller. Protocol invocations enter the new campaign engine.
The campaign defaults to PCAP output, accepts explicit source/destination/BSSID
addresses, and writes reproducible synthetic timestamps. Redirect stdout or use
`--output`; inspect `--protocol-help` for all options.

In the full build, explicit `--interface NAME --channel N` selects live WiFi injection
for linktype 105. It opens and configures an existing monitor interface through the
existing WiFi backend. Ethernet currently has PCAP delivery only. No live radio or
embedded-board validation was performed for this change.

## Extension contract

Add a C source file under `owfuzz/src/protocols/modules/`, export
`const struct ow_family ow_module_<filename_without_extension>`, and define its
frame descriptor array. The Makefile discovers source files and generates portable
registration code without constructors or dynamic loading. Adding a frame to a new
family means adding its builder and descriptor to that module; adding a family
means adding a module. Neither requires changing the engine, CLI, or registration
list. A module filename must match `[a-z][a-z0-9_]*`.

```c
#include "../protocol.h"
static int example(struct ow_context *context, struct ow_packet *packet)
{
    (void)context;
    packet->data[0] = 42;
    packet->len = 1;
    return 0;
}
static const struct ow_frame frames[] = {{65536, "example", example}};
const struct ow_family ow_module_example = {"example", 147, frames, 1};
```

Linktype 147 is PCAP USER0 in this illustrative module, not a protocol assignment.
Frame IDs are 32 bits and scoped to a family; names and IDs must be unique inside
that family. Families must have distinct nonempty names, nonempty frame tables,
nonzero link types, and nonnull builders. Registration rejects duplicates and is
performed before a campaign; descriptors must outlive the registry. Keep registration
single-threaded and treat the registry as immutable afterward.

A builder writes up to 4096 bytes, sets a nonzero length, and returns zero on success.
It must check capacity *before* writing; the engine's postcondition checks cannot
undo an out-of-bounds write inside a faulty plugin. Received bytes and arbitrary
per-campaign state can be passed through `ow_context`; the CLI campaign path does
not yet implement receive-driven protocol state machines. The legacy adapters
preserve global WiFi state and are not reentrant. Native new modules can keep state
in `context.user` and deterministic randomness in `context.random_state`.

Mutation is independently selected (`none`, `bitflip`, `truncate`). A transport
accepts one explicit linktype and a send callback; incompatible packets are rejected
before sending. Supporting an additional physical medium still requires a transport
implementation and hardware validation. This is an extensible framework, not an
assertion of support for every existing protocol or physical layer.

## Migration of existing WiFi frames

`frames/legacy_registry.c` centralizes the 42 legacy frame entries, canonical
configuration names, names for logging, baseline builders, and save/load callbacks.
Frame creation, default creation, both configuration sections, logging names, and
state dispatch use that metadata instead of repeated switches. Unsupported reserved
frame entries enabled in configuration now produce an error instead of selecting
an empty builder. Disabled reserved entries remain accepted. Configuration arrays
retain the existing 64-entry bound. The linker also discovers frame source files
automatically, removing its old hardcoded object list. To extend the legacy family,
add a builder and a metadata entry with its declaration in the adapter module.

One existing entry, `control_frame_extension`, is an empty stub. The other 41
builders emit packets in the integrated offline smoke test. The registry preserves
the stub for compatibility; a new-engine campaign selecting it fails on its empty
result. Registration alone does not certify that a builder implements its protocol.

New modules use the protocol engine. The old interactive AP/STA/MITM/P2P/AWDL/mesh
state machines remain WiFi-specific; adding a native module does not automatically
teach those state machines about its protocol. The new campaign mode deliberately
has a separate option namespace to preserve existing use.

Legacy `-f` argument handling/fall-through, missing `-r` parsing/seed forwarding, and test-type error formatting are corrected.
The legacy combined mode `-T 3` remains unsupported: the existing controller has no
combined-mode execution path, despite advertising it in its old help text. Small pre-existing compiler errors are also corrected: EAPOL
64-bit fields are passed by address, timing advertisement uses its declared pointer
type, and `init_ping_sock` is called without an argument.

## Experimental 802.11be scope

The `802.11be` module generates a probe-response corpus containing a Basic Multi-Link
extension element and a deliberately invalid Common Info Length case. The small
baseline element uses extension ID 107, Basic control type, and seven bytes of common
information (length plus MLD MAC). It is an element-level test seed, not a complete
standards-conformant AP advertisement or full Multi-Link Operation implementation.
It omits EHT capability/operation negotiation, per-link profiles, multi-radio scheduling,
association, and link synchronization. `none` preserves the baseline corpus; generic
mutation can change any byte, including headers. No claims of successful MLO
interoperation or new vulnerabilities are made.

Layout references:

- [hostapd EHT Multi-Link implementation](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/c0f5d41155bda2f028d650958a1cccff9a557143/src/ap/ieee802_11_eht.c)
- [hostapd element definitions](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/src/common/ieee802_11_defs.h)

## Validation

`make -C owfuzz test-protocols` tests duplicate registration, namespaced lookup,
packet bounds, deterministic seed-zero mutations, PCAP headers/record lengths,
invalid CLI inputs, and transport isolation. It compiles a previously unknown
module and runs it without modifying any core source or build list.

A frozen pre-refactor frame-dispatch fixture compares all 42 migrated adapters using
instrumented builders and both absent/present received packets. This verifies
callback selection and argument forwarding; it does not prove every original frame
builder is memory-safe or verify over-the-air behavior. Regression tests remain
necessary even when extension points eliminate edits to existing code.

With full dependencies available, `make -C owfuzz test-integrated` additionally
exercises the fully linked executable, all 41 packet-producing legacy builders,
the known empty stub, and reproducible Ethernet/Multi-Link campaigns. The core
registry tests also passed AddressSanitizer/UndefinedBehaviorSanitizer; leak checking
was disabled because the execution environment runs under ptrace. Existing legacy
compiler warnings remain, and live hardware behavior remains unverified.
