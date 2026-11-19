# From WiFi Frame Dispatch to Protocol-Family Extensibility: A Pattern-Based Refactoring of Owfuzz in C

**Marco Lira**  
Centro Federal de Educação Tecnológica Celso Suckow da Fonseca (CEFET/RJ)  
Brazil

Research manuscript - draft for author review. 20 October 2026.  
Software snapshot: `test/add-features`, commit `e98b03e`; baseline: `10af304`.

## Abstract

Protocol fuzzers need to evolve as communication standards introduce new messages and execution contexts. Extensibility at the frame-dispatch level, however, does not by itself remove assumptions about a particular protocol or transmission medium. This paper presents a pattern-based refactoring of Owfuzz that introduces a protocol-neutral campaign path alongside its existing interactive WiFi controller. The design combines factory callbacks, independent mutation and transport strategies, an explicit registry of protocol-family descriptors, and adapters for legacy frame constructors. Portable build-time discovery replaces manually maintained module lists. The implementation exposes 42 legacy WiFi entries, an Ethernet ARP module, and two experimental IEEE 802.11be Multi-Link element cases. An integration test adds and executes an unknown family without editing the engine, command-line interface, or Makefile. Offline checks exercise all 42 migrated dispatch adapters, while 41 real legacy builders produce nonempty PCAP records and one existing empty stub is rejected. Fresh Lizard measurements show that the aggregate cyclomatic complexity of three legacy dispatch functions decreases from 106 to 7; the summed function complexity across the broader production-C scope decreases only from 2,190 to 2,173, illustrating redistribution rather than elimination of complexity. The contribution is an extensible and testable architecture, not complete Multi-Link Operation support. A paired developer-effort study is specified and instrumented, but no participant-time reduction or new vulnerability discovery is claimed.

**Keywords:** protocol fuzzing; software architecture; C; Strategy; Registry; factory callbacks; embedded-system integration; extensibility.

## 1 Introduction

Owfuzz generates WiFi test traffic for access points and stations and can operate with monitor-mode adapters or the OpenWiFi platform [1,4]. Its combination of packet construction, protocol interaction, and hardware access makes it a useful case for examining the relationship between software architecture, security testing, and embedded deployment. These concerns meet at the extension boundary: a new protocol feature should not require unrelated control logic to learn how its packets are represented.

<!-- COLUMN -->

A prior manuscript by Moura et al. [2] studies Owfuzz's frame dispatcher using Factory Method, Strategy, and Registry concepts. It also identifies protocol-level Abstract Factory organization as a possible continuation. The present work addresses that direction through an independently inspected repository branch. Its starting point is the switch-based snapshot `10af304`, not an assumption that the earlier manuscript's implementation is already present. The earlier authors' measurements and hardware experiments remain their results; they are not observations of this branch.

The distinction matters because frame classes and protocol families are different extension dimensions. Management, control, and data are classes within IEEE 802.11. IEEE 802.11be is an amendment within the same broad WiFi family, while Ethernet introduces a different link-layer representation. The implementation therefore uses named family/profile descriptors and demonstrates two packet encodings, rather than presenting three module names as three unrelated network technologies.

This paper investigates three research questions. **RQ1:** Can the campaign engine accept another family without edits to orchestration and build lists? **RQ2:** Can legacy dispatch behavior be retained while separating packet construction, mutation, and delivery? **RQ3:** What evidence supports structural improvement, and what further work is needed to measure developer effort?

The contributions are a C extension contract, an adapter-based migration of legacy dispatch and metadata, executable cross-family extension tests, and a reproducible static analysis of two exact commits. A separate study protocol defines how to compare the time needed to add frames and families. This separation keeps demonstrated properties distinct from future empirical claims.

## 2 Background and Related Work

The GoF catalog describes reusable solutions including Strategy, Factory Method, Abstract Factory, and Adapter [3]. Here their intent is expressed through C structures, descriptors, and function pointers. A family descriptor groups compatible products in an Abstract Factory-like role, while a selected frame callback constructs a packet. Mutation and delivery callbacks are independent Strategies. This terminology describes the architecture's responsibilities; the code does not implement a class hierarchy or the literal subclass-based form of Factory Method.

A Registry supplies the association between names and descriptors. It is a separate mechanism from the GoF patterns. Compared with the constructor-attribute approach discussed in [2], explicit generated registration makes initialization visible and avoids dependence on compiler startup attributes. The contribution is the evaluated adaptation to this repository, not a claim that registries or callback-based protocol modules are novel.

<!-- PAGE -->

## 3 Problem Analysis

In the baseline, knowledge of an IEEE 802.11 frame is repeated across creation switches, naming switches, configuration readers, state dispatch, and a hardcoded linker object list. The same frame identity must remain consistent in each place. A local addition can therefore require changes to code that neither constructs nor processes the new packet. Existing WiFi addresses and type discriminators also shape the public interfaces.

Removing only a creation switch would leave two difficulties. First, names, configuration, and lifecycle callbacks could still drift apart. Second, a dispatcher whose arguments and output assume IEEE 802.11 would still be unsuitable for an Ethernet frame. The problem is both repeated metadata and a protocol-specific orchestration boundary.

The refactoring addresses these difficulties in layers. It preserves the old interactive path through adapters, centralizes legacy metadata, and introduces a separate campaign engine whose packet container carries serialized bytes and an explicit link type. Figure 1 shows that boundary. The generic path does not attempt to reinterpret an unfamiliar packet as an IEEE 802.11 header.

```text
Family/frame registry
        |
Builder callback (legacy adapter or native module)
        |
Mutation strategy
        |
Transport strategy + link-type check
        |
PCAP output or WiFi send callback
```

*Figure 1. The campaign path resolves a family and frame, invokes a construction callback, applies a mutation strategy, and checks the selected transport before delivery. The legacy interactive controller remains a separate WiFi-specific path.*

### 3.1 Extension boundaries

The engine owns registration validation, frame lookup, packet postconditions, and delivery compatibility. A module owns its frame descriptor table and builders. A transport owns the medium-specific send operation. These responsibilities allow a new builder to reuse existing mutation and PCAP delivery without modifying campaign control flow.

The boundaries are intentionally limited. A descriptor does not implement a receiver, protocol negotiation, or a device driver. A new physical medium may still need a transport adapter, and a stateful protocol may require a controller beyond the provided command-line campaign loop. Generic representation is a prerequisite for those extensions, not evidence that they already exist.

<!-- COLUMN -->

## 4 Proposed Architecture

### 4.1 Family and frame factories

A family is represented by `ow_family`: a name, a link type, a frame table, and its size. Each `ow_frame` has a 32-bit identifier, a name, and a builder callback. IDs are scoped to the family, so the extension contract is not limited to a one-byte WiFi discriminator. Family and frame names are resolved independently; the engine then validates that the selected frame belongs to the selected family.

The following abbreviated declarations show the actual callback boundary. The context contains addresses used by the supplied examples, iteration and random state, optional received bytes, and a user pointer. Although address convenience fields are currently six bytes, a module can use private state and the byte container for another representation; a generalized addressing API remains future work.

```c
typedef int (*ow_builder)(
    struct ow_context *, struct ow_packet *);

struct ow_frame {
    uint32_t id;
    const char *name;
    ow_builder build;
};
struct ow_family {
    const char *name;
    uint32_t linktype;
    const struct ow_frame *frames;
    size_t count;
};
```

*Listing 1. A family groups frame factories without exposing their construction algorithms to the campaign engine.*

### 4.2 Independent strategies and contracts

An `ow_mutator` selects `none`, `bitflip`, or `truncate`. An `ow_transport` declares a supported link type, private state, and a send callback. Packet buffers hold at most 4,096 bytes. The generator rejects empty results, excessive reported lengths, changed link types, and foreign frame descriptors. Delivery rejects a packet whose link type does not match the transport.

These checks are postconditions, not memory isolation. A faulty C plugin can write out of bounds before reporting its length; builders must enforce capacity before writing. The default registry admits at most 32 families, uses linear family/frame searches, and checks duplicate frame identities with pairwise comparisons. This bounded implementation favors clarity over claims of constant-time lookup or universal scale.

### 4.3 Explicit registration

The build discovers module source files and generates calls to `ow_register`. Each file exports a family symbol derived from its filename. Registration rejects missing callbacks, empty tables and names, and duplicate names or IDs. Initialization occurs explicitly before execution; descriptors must outlive the registry. No dynamic loader or constructor attribute is required.

<!-- PAGE -->

## 5 Implementation

### 5.1 Preserving the legacy interface

`frames/legacy_registry.c` supplies the compatibility layer. Each entry groups the legacy wire ID, configuration name, symbolic and display names, creation and optional baseline callbacks, and save/load callbacks. The existing public creation functions now perform metadata lookup and callback dispatch. Both AP and station configuration readers use a common bounded parser; logging and state dispatch also consult shared metadata.

The registry has 42 legacy entries. One, `control_frame_extension`, is an inherited stub that returns an empty packet. The other 41 emit packets in the integrated offline checks. Counting registered entries as fully implemented frame generators would conceal this distinction. The adapter retains the stub for compatibility, while the new engine rejects its empty output.

Most constructors are reused directly, preserving their WiFi-specific globals and behavior. A short received probe-request buffer is guarded before extracting its body. The compatibility work also corrects existing `-f`/`-r` parsing issues, seed forwarding, and compiler-detected pointer or call-signature errors. It is consequently more than a mechanically identical movement of source lines. The dispatch regression tests isolate the forwarding behavior, rather than claiming whole-program equivalence.

Frame implementation objects are discovered automatically by the linker build list. Adding another legacy implementation still requires its constructor and metadata entry, including an appropriate declaration. Native modules instead own a complete frame table and use the generic campaign contract. Existing interactive AP/STA and other WiFi modes continue through the old controller; adding a native module does not automatically extend those state machines.

### 5.2 Module discovery and campaigns

A source file under `protocols/modules/` exports `ow_module_<stem>`. Generated registration is refreshed when the module set changes, including deletions. The integration fixture creates an unknown family with frame ID 65,536 and PCAP USER0 link type 147, builds it using the real discovery rules, and executes it. It then removes that module, adds another, rebuilds, and verifies the listing. The engine, CLI, and Makefile are unchanged during this test.

The command-line entry point selects the generic campaign path when protocol options are present and otherwise preserves legacy invocation. The standalone build omits the legacy adapter and radio dependencies. The full executable includes the adapter and a live WiFi send callback. This organization makes extension checks possible without allocating a radio interface.

<!-- COLUMN -->

### 5.3 Supplied families and profiles

Table 1 separates descriptor coverage from operational support. The Ethernet module constructs a 60-byte, padded ARP request using documentation-network IPv4 addresses. It provides a concrete non-WiFi representation rather than another wireless frame class. Its current transport is PCAP output; Ethernet live injection is not implemented.

| Module | Cases | Encoding / current delivery |
| --- | ---: | --- |
| 802.11 legacy | 42 | WiFi (105); PCAP / live adapter |
| Ethernet | 1 | Ethernet (1); PCAP only |
| 802.11be profile | 2 | WiFi (105); PCAP / live adapter |

*Table 1. Modules in the full executable. The 802.11be label identifies an experimental WiFi profile, not an independent link-layer family.*

The 802.11be profile builds a 50-byte probe-response seed carrying a Basic Multi-Link extension element. The element uses extension ID 107 and seven bytes of common information, including the length byte and MLD MAC address. A second case deliberately sets Common Info Length to 255 while retaining the shorter packet. The layout is informed by the hostapd EHT implementation [6]. These are element-level test cases, not complete standards-conformant access-point advertisements or Multi-Link Operation sessions.

IEEE 802.11be extends WiFi with Extremely High Throughput capabilities [7]. The present profile does not implement EHT capability negotiation, per-link station profiles, association across links, synchronization, or multi-radio scheduling. Because it remains serialized as an IEEE 802.11 packet, it uses the same link type as the legacy WiFi module. Its value in this experiment is exercising amendment-specific construction behind an unchanged engine.

### 5.4 Reproducible corpora

The new CLI accepts a family, frame, mutation, 32-bit seed, count, optional addresses, and an output path. A per-campaign linear congruential generator supplies deterministic choices, including seed zero. PCAP records use synthetic iteration-based timestamps, so repeated native-module campaigns with identical options produce identical bytes. This is corpus reproducibility, not reproduction of device timing or radio conditions.

The `none` mutation leaves a builder's output unchanged; it does not certify that output as valid protocol traffic. This is especially relevant to legacy constructors, which already generate fuzzed content. The PCAP writer records the module's explicit link type, avoiding interpretation of Ethernet payloads as WiFi frames [8]. The full build can instead send link-type-105 packets through a named WiFi interface. That live path was not exercised in this evaluation.

<!-- PAGE -->

## 6 Evaluation

### 6.1 Method and measurement scope

Static analysis compares tracked source at baseline `10af304` and refactored commit `e98b03e` [5]. Lizard 1.24.1 [9] applies the same path-filtering rule at both revisions. The production scope contains C files under `owfuzz/src`, excluding bundled `hostapd_lib`, test directories, protocol test files, frozen fixtures, and generated registration. It includes the newly relocated adapters and generic engine. Linux WiFi backends, Python tooling, and headers are outside this scope. File NLOC and summed per-function CCN are reported separately; neither measures developer time.

Automated checks were rerun on 20 October 2026 in an x86-64 Linux environment with GCC 15.2.0 and Python 3.14.4. The hardware-free suite and integrated suite completed successfully against the available executable. The integrated make invocation reused up-to-date build products; it was not a fresh rebuild of every object during this paper-preparation run. Earlier branch implementation also completed full linking after supplying the missing development library temporarily. No clean baseline build or controlled device campaign was run for this paper.

### 6.2 Dispatch complexity

Table 2 reproduces the three-function comparison used to examine local dispatch. Aggregate CCN falls from 106 to 7, a 93.4% reduction; NLOC falls from 284 to 22, a 92.3% reduction. These are measurements of this branch and differ from the earlier manuscript's results [2]. They should not be substituted for a whole-program complexity claim.

| Function | NLOC before | NLOC after | CCN before | CCN after |
| --- | ---: | ---: | ---: | ---: |
| return_frame_type | 93 | 5 | 44 | 2 |
| get_frame | 146 | 9 | 46 | 2 |
| get_default_frame | 45 | 8 | 16 | 3 |
| Total | 284 | 22 | 106 | 7 |

*Table 2. Lizard measurements for legacy functions in `frames/frame.c`. CCN is cyclomatic complexity; NLOC excludes comments and blank lines under the analyzer's rules.*

The improvement reflects removal of repeated selection logic. It does not remove the frame algorithms or their indirect calls. Lookup, common parsing, module admission, and contract checks now hold responsibilities previously repeated or absent. The evidence supports a simpler extension-facing dispatcher, not a proportional reduction in all testing or security risk.

<!-- COLUMN -->

### 6.3 Broader source trade-offs

Table 3 includes the relocated adapters and the new engine in the declared production scope. Source-file and function counts increase, but file NLOC decreases by 1.5%. Summed per-function CCN decreases by only 17, or 0.8%. Thus the strong local dispatch improvement coexists with a small aggregate change. Registration and validation add explicit decision paths, while adapters increase the number of small functions.

| Production-C measure | Before | After |
| --- | ---: | ---: |
| Source files | 60 | 66 |
| Functions | 288 | 358 |
| File NLOC | 12,150 | 11,966 |
| Summed function CCN | 2,190 | 2,173 |

*Table 3. Broader production-C scope. Summed function CCN is an aggregate analyzer output, not the cyclomatic complexity of a single program graph.*

For example, the shared configuration helper has CCN 16, the generic registration function CCN 18, and `ow_generate` CCN 18. Concentrating validation into named boundaries can make responsibilities easier to locate even when it does not erase decisions. The registry still directly depends on its legacy constructors; coupling has moved out of orchestration. No new cflow-derived percentage is claimed.

### 6.4 Functional and extension checks

The protocol suite checks duplicate registration, lookup, frame membership, packet-length postconditions, deterministic seed-zero mutations, mismatched transports, CLI rejection, and PCAP encoding. Its extension fixture demonstrates RQ1 for a self-contained module using the existing output transport: one added module source and zero engine/CLI/Makefile edits.

The frozen pre-refactor fixture tests all 42 legacy dispatch entries with instrumented constructors for absent and present received packets, giving 84 dispatch comparisons. These checks verify constructor selection and argument forwarding. The real-builder integration separately checks 41 nonempty PCAP records and the expected failure of the empty stub. Two ten-packet native campaigns are compared byte-for-byte for repeatability. No inference about all frame contents follows from a valid capture-record envelope.

The protocol-core test also passes AddressSanitizer and UndefinedBehaviorSanitizer. Leak detection is disabled because of the traced execution environment. This sanitizer run covers that test binary, not the whole legacy code base or every malformed-input path. The metrics reporter's three unit tests check pairing, duplicate observations, and empty reports. They establish reporter behavior, not empirical effort savings.

<!-- PAGE -->

## 7 Developer-Effort Study Protocol

RQ3 requires separating structural extension cost from observed implementation time. The module fixture establishes that a specific extension can avoid core edits. It does not establish how quickly a developer understands the interface, implements a correct protocol, writes tests, or diagnoses a failure. The branch therefore provides `tools/extension_metrics.py` and a study protocol rather than a fabricated time comparison.

### 7.1 Tasks and controls

Two primary tasks are proposed. A frame task adds a specified frame with fixed expected bytes, named selection, and a correctness test. A family task adds a non-WiFi descriptor and bounded builder with its required PCAP encoding. A third, optional received-packet-dependent task explores limitations that the current CLI does not resolve. Requirements and acceptance checks must be equivalent across baseline and refactored variants.

Each trial begins from a clean checkout of the assigned revision. The baseline uses `10af304`; the refactored variant uses the reviewed branch snapshot. Participants, tasks, trial numbers, starting commits, and variant order are recorded. At least three repetitions per task and participant are proposed, with order counterbalanced across participants to reduce learning effects. This repetition count is a starting protocol, not a power analysis or a claim of statistical sufficiency.

Timing should begin when the task is first read and end when its acceptance checks pass. Whether documentation, test writing, and interruptions are included must be fixed before data collection. A time limit and incomplete-task policy are needed because a family extension may require substantial baseline restructuring. Failure or incompletion must be reported separately, never encoded as zero successful effort.

### 7.2 Recorder and comparisons

The recorder uses monotonic elapsed time, checks the Linux boot identity, and rejects trials spanning a reboot. State and results live outside the checkout. Finishing a trial stores elapsed seconds, validation notes, commit identity, changed-file and line counts, and edits to a published core-file set. Raw results use JSON Lines. File and line counts are syntactic observations, not semantic edit counts or productivity scores.

Records are paired by participant, task, and trial. The report produces per-variant medians, rejects duplicate keys, and identifies unpaired observations. For a completed pair, time reduction is `(T_baseline - T_refactored) / T_baseline x 100`. A negative value means the refactored trial took longer. No participant observations have yet been collected, so no measured percentage of development time saved is reported.

<!-- COLUMN -->

## 8 Discussion and Embedded-System Relevance

### 8.1 What became extensible

RQ1 is supported by an executable addition-and-removal test for a new family. RQ2 is supported at the dispatch boundary by frozen-fixture comparisons and offline real-builder checks. The architecture gives a module control over packet construction while keeping selection, mutation, and delivery reusable. It also reduces opportunities for inconsistent names or missing switch branches by centralizing legacy metadata.

The evidence is narrower than a universal-fuzzer claim. The supplied address convenience fields are WiFi/Ethernet-oriented; physical transports are not automatically discovered; the CLI lacks receive-driven protocol state machines; and the legacy builders retain global state. A complete family implementation may need protocol parsing, timing, connection management, and new device support. Those components can fit behind clearer interfaces, but are not supplied by a registry entry alone.

The 802.11be example illustrates a related distinction. Reusing WiFi serialization with a new information element is useful, yet it does not by itself demonstrate an unrelated protocol family. The Ethernet module provides the stronger representation-boundary test. Neither example supports a claim that every current protocol is covered, that fuzzing effectiveness improved, or that no comparable open-source framework exists.

### 8.2 Relationship to embedded deployment

OpenWiFi combines software and FPGA-based WiFi functions and can expose a Linux-compatible radio interface [10]. Owfuzz can run as a userspace application on that platform. The embedded system is the integrated processor, operating system, programmable logic, radio, and application; the C application alone is not the complete embedded system.

This work connects embedded use to architecture through explicit transport and memory boundaries. Fixed packet capacity and bounded registration make limits visible, while PCAP execution enables tests without the board. These properties are design choices, not measurements of low memory use, energy efficiency, hard real-time behavior, or ARM performance. The C core's ordinary callback interfaces avoid a compiler-constructor requirement, but the whole application still depends on platform services; the build generator uses Python and the effort recorder is Linux-specific.

Board deployment should evaluate cross-compilation, available memory, packet rates, adapter behavior, and host/FPGA timing under controlled conditions. An end-to-end Multi-Link experiment additionally needs suitable radio and peer capabilities. Until then, the demonstrated connection to embedded systems is deployment-oriented and architectural. No board benchmark, live target fault, or over-the-air vulnerability result is attributed to this branch.

<!-- PAGE -->

## 9 Threats to Validity

**Construct validity.** Small dispatchers can coexist with substantial validation and adapter logic elsewhere. The whole-scope measurements and explicit helper CCNs address this risk but do not measure comprehensibility directly. Changed files and lines are proxies for extension footprint; only controlled participant observations can measure task time. Pattern names describe design intent and are not independent evidence of maintainability.

**Internal validity.** The branch includes bounded configuration handling, CLI repairs, and small type/signature corrections alongside the architectural refactoring. Any later productivity or behavioral difference cannot automatically be attributed to one pattern. Frozen stubs test forwarding, not the full internal semantics of the real constructors. The additional short-packet guard intentionally changes unsafe behavior, so strict equivalence across every input is not claimed.

**External validity.** The extension fixture is small and stateless. Ethernet ARP and a Multi-Link element corpus do not represent the difficulty of a complete stateful protocol stack. Execution on one x86-64 environment does not establish behavior on embedded ARM/FPGA hardware. Only one selected generated packet per real legacy constructor is checked in the integrated smoke test; long campaigns can encounter additional states and defects.

**Reproducibility.** Commit IDs, analyzer version, filtering rules, raw metrics, and executable tests define the observations. Generated code and tests are excluded from the production-C totals; Python tooling is also outside them. Other analyzers or scope definitions can produce different totals. A successful run with cached objects is weaker build evidence than a clean rebuild. Neither the earlier paper's hardware validation nor its reported complexity reductions are reused as measurements of this branch.

## 10 Conclusion

The `test/add-features` branch moves Owfuzz from repeated frame-selection logic toward a protocol-family extension contract. Family-scoped factories, independent strategies, explicit registration, and legacy adapters allow an unknown module to execute without edits to the generic engine, CLI, or build lists. Offline evidence retains 42 legacy dispatch entries, confirms packet output from 41 real builders, and identifies the remaining empty stub instead of hiding it.

The measured local reduction from 106 to 7 CCN is accompanied by a much smaller aggregate change. This supports a claim about localized architectural simplification, not an equivalent gain in security or developer speed. The next steps are the controlled effort study, receive-driven protocol controllers, and embedded/hardware evaluation. Complete MLO support and market-novelty claims remain outside the demonstrated results.

<!-- COLUMN -->

## References

[1] Hongjian Cao, Lin Huang, Shuwei Hu, Shangcheng Shi, and Yujia Liu. 2023. Owfuzz: Discovering Wi-Fi Flaws in Modern Devices through Over-The-Air Fuzzing. *Proceedings of WiSec '23*, 263-273. [doi:10.1145/3558482.3590174](https://doi.org/10.1145/3558482.3590174).

[2] Nilton Moura, Jean D'Elboux, Thatyanne Prado, Diego Cardoso Borda, and Cláudia Werner. 2026. *Refactoring a WiFi Protocol Fuzzer for Extensibility with GoF Design Patterns*. COS820 manuscript, supplied reference document. No publication status is inferred.

[3] Erich Gamma, Richard Helm, Ralph Johnson, and John Vlissides. 1994. *Design Patterns: Elements of Reusable Object-Oriented Software*. Addison-Wesley. [Publisher record](https://www.informit.com/store/design-patterns-elements-of-reusable-object-oriented-software-9780201633610).

[4] Alipay. *Owfuzz: a WiFi Protocol Fuzzing Tool*. Research baseline `10af304`. [Upstream repository](https://github.com/alipay/Owfuzz). Accessed 20 October 2026.

[5] Marco Lira. 2026. *Protocol-family extension of Owfuzz*. Research software, branch `test/add-features`, commit `e98b03e`. Local artifact evaluated in this paper; no public release URL is asserted.

[6] Hostapd contributors. *EHT and Basic Multi-Link element implementation*. `src/ap/ieee802_11_eht.c`, snapshot `c0f5d41155bda2f028d650958a1cccff9a557143`. [Source](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/c0f5d41155bda2f028d650958a1cccff9a557143/src/ap/ieee802_11_eht.c). Accessed 20 October 2026.

[7] IEEE 802.11 Working Group. *Task Group BE: Extremely High Throughput*. [Working-group report](https://www.ieee802.org/11/Reports/tgbe_update.htm). Accessed 20 October 2026.

[8] The Tcpdump Group. *libpcap link-layer type definitions*. `pcap/dlt.h`. [Source](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h). Accessed 20 October 2026.

[9] Terry Yin and contributors. *Lizard: code complexity analyzer*. Version 1.24.1 used for this evaluation. [Repository](https://github.com/terryyin/lizard). Accessed 20 October 2026.

[10] OpenWiFi contributors. *openwifi: Linux mac80211-compatible IEEE 802.11 SDR design*. [Repository](https://github.com/open-sdr/openwifi). Accessed 20 October 2026.

## Artifact Availability and Disclosure

The companion metrics JSON and measurement script identify the exact production-C scope and provide function-level observations for both commits. The branch includes `test-protocols`, `test-integrated`, a frozen dispatch fixture, and the developer-effort recorder. Reproduction requires the local Git history, Lizard 1.24.1, build dependencies for integrated checks, and the command sequence below.

```sh
make -C owfuzz test-protocols
make -C owfuzz test-integrated
# From the repository root, with Lizard installed:
python3 output/pdf/measure_branch.py
```

AI assistance was used in code development, analysis scripting, and manuscript drafting. This document is a research draft for author review; no institutional endorsement or completed participant study is implied.
