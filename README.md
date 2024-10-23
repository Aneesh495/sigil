# Sigil

[![CI](https://github.com/Aneesh495/sigil/actions/workflows/ci.yml/badge.svg)](https://github.com/Aneesh495/sigil/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Raku](https://img.shields.io/badge/Raku-2024.07+-purple.svg)](https://raku.org)
[![C Standard](https://img.shields.io/badge/C-C11-00599C.svg)](https://en.cppreference.com/w/c/11)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)](https://www.python.org)

**Sigil** is a high-performance network telemetry, deep packet dissection, stream reassembly, and filter compilation engine. It marries high-level declarative protocol grammars in Raku with a lockless C11 memory-mapped capture core capable of processing over **22 million packets per second**, alongside an asynchronous Python terminal telemetry console.

```
                      +------------------------------------------+
                      |         Physical NIC / PCAP Trace        |
                      +------------------------------------------+
                                           |
                                           v
    +-------------------------------------------------------------------------------+
    |                   C11 Zero-Copy Capture Core (capture/)                       |
    |                                                                               |
    |  +-------------------+       +--------------------+       +----------------+  |
    |  | mmap PCAP Engine  | ----> | SPSC Ring Buffer   | ----> | POSIX Shm IPC  |  |
    |  | (22.3M pkts/sec)  |       | (Lockless, 64B Pad)|       | (/sigil_ring)  |  |
    |  +-------------------+       +--------------------+       +----------------+  |
    +-------------------------------------------------------------------------------+
                                           |
                                           v
    +-------------------------------------------------------------------------------+
    |                     Raku Dissection & Analysis Engine                         |
    |                                                                               |
    |  +-------------------+       +--------------------+       +----------------+  |
    |  | Buffer Cursor     | ----> | Protocol Pipeline  | ----> | TCP Reassembly |  |
    |  | Zero-Copy Slicing |       | L2 - L7 Dissectors |       | Out-of-Order   |  |
    |  +-------------------+       +--------------------+       +----------------+  |
    |                                      |                             |          |
    |                                      v                             v          |
    |  +-------------------+       +--------------------+       +----------------+  |
    |  | BPF Filter AST    |       | Stream HeavyHitters|       | Shannon Entropy|  |
    |  | Boolean Optimizer |       | Space-Saving Alg   |       | Anomaly Detect |  |
    |  +-------------------+       +--------------------+       +----------------+  |
    +-------------------------------------------------------------------------------+
                                           |
                                           v
    +-------------------------------------------------------------------------------+
    |              Export Subsystem & Python Visualizer (dashboard/)                |
    |                                                                               |
    |  +-------------------+   +--------------------+   +------------------------+  |
    |  | Wireshark Columns |   | Structured NDJSON  |   | Curses Terminal UI     |  |
    |  | Colored Hex Dump  |   | Tabular CSV Output |   | Rolling Sparklines/BPS |  |
    |  +-------------------+   +--------------------+   +------------------------+  |
    +-------------------------------------------------------------------------------+
```

---

## Key Highlights

- **Declarative Protocol Modeling**: Dissectors for 25+ protocols spanning L2 through L7 implemented using Raku native grammars, pattern matching, and typed subsets.
- **Microsecond Memory Slicing**: Custom `BufferCursor` with decontainerized mark/rewind checkpoints and bounded slice operations without copying byte buffers.
- **Full Out-of-Order TCP Stream Reassembly**: RFC 9293 sequence space tracking, overlapping interval segment splicing, window gap detection, and two-way stream payload collation.
- **Compiling Filter DSL**: BPF-like query language (`tcp.port == 443 && ip.len > 128 || dns.qr == 1`) parsed via Raku grammars into an abstract syntax tree with short-circuit boolean evaluation.
- **Lockless C11 Ingestion Core**: Cacheline-isolated (`alignas(64)`) Single-Producer Single-Consumer (SPSC) ring buffer in shared POSIX memory, benchmarking at **22.34 million ops/sec** with zero mutex contention.
- **Statistical Flow Analysis**: Streaming Space-Saving algorithm for top-talker frequency estimation and sliding-window Shannon entropy calculation for encrypted or tunneled traffic detection.
- **Zero-Dependency CLI Suite**: Comprehensive command-line tools for dissection, stream extraction, filter verification, and PCAPNG block inspection.

---

## Supported Protocols

| Layer | Protocol | Standard / RFC | Features & Decoded Fields |
| :--- | :--- | :--- | :--- |
| **L2: Link** | Ethernet II | IEEE 802.3 | MAC addresses, EtherType dispatch, FCS validation |
| | IEEE 802.1Q | IEEE 802.1Q | VLAN ID, Priority Code Point (PCP), Drop Eligibility |
| | IEEE 802.1ad | QinQ Double Tag | Outer and inner VLAN tags, nested EtherType parsing |
| | ARP | RFC 826 | Hardware/protocol types, opcode, gratuitous ARP check |
| | LLDP | IEEE 802.1AB | Chassis ID, Port ID, TTL, System Name/Capabilities |
| **L3: Network**| IPv4 | RFC 791 | Header length, ToS/DSCP, flags, fragments, checksum |
| | IPv6 | RFC 8200 | Flow label, traffic class, extension header traversal |
| | ICMPv4 | RFC 792 | Echo, destination unreachable, redirect, checksum |
| | ICMPv6 | RFC 4443 / 4861 | Neighbor Solicitation/Advertisement, Router discovery |
| | IGMP | RFC 1112 / 2236 / 3376 | v1/v2/v3 Membership Report, Query, Leave Group |
| **L4: Transport** | TCP | RFC 9293 | Ports, seq/ack numbers, SYN/ACK/FIN flags, options (MSS, WS, SACK, TS) |
| | UDP | RFC 768 | Length, ports, optional UDP checksum validation |
| | SCTP | RFC 4960 | Verification tag, chunk headers (DATA, INIT, SACK) |
| | QUIC | RFC 9000 | Long/Short header format, version negotiation, connection IDs |
| **L7: Application** | DNS | RFC 1035 | Question, answer, authority, additional RRs, label decompression |
| | DNSSEC | RFC 4034 | RRSIG, DNSKEY, DS, NSEC, NSEC3 record parsing |
| | DHCP | RFC 2131 | Opcode, transaction ID, client/server IPs, option decode |
| | NTP | RFC 5905 | Stratum, leap indicator, poll interval, 64-bit timestamps |
| | HTTP/1.1 | RFC 7230 | Request/response method, status code, URI, headers |
| | TLS 1.3 / 1.2| RFC 8446 | Handshake records, ClientHello Server Name Indication (SNI) |
| | WebSocket | RFC 6455 | FIN bit, opcode, masking key, payload de-masking |
| | MQTT | v3.1.1 / v5.0 | Connect, publish, subscribe, QoS levels, packet IDs |
| | Redis RESP | RESP2 / RESP3 | Simple strings, errors, integers, bulk strings, arrays |
| | BGP-4 | RFC 4271 | OPEN, UPDATE, NOTIFICATION, KEEPALIVE, AS path |
| | SSH | RFC 4253 | Client/server version exchange, binary packet length |
| | Syslog | RFC 3164 / 5424 | Facility, severity, priority calculation, ISO timestamps |

---

## System Architecture

```
                  +-----------------------------------------+
                  |           Raw Network Stream            |
                  +-----------------------------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
         +--------------------+                  +--------------------+
         |   PCAP / PCAPNG    |                  |  Live C SHM Ring   |
         |    Trace Files     |                  |   Memory Mapped    |
         +--------------------+                  +--------------------+
                   |                                       |
                   +-------------------+-------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |       Sigil::Core::Buffer         |
                     |      Zero-Copy BufferCursor       |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |     Dissector Pipeline Engine     |
                     |   (L2 -> L3 -> L4 -> L7 Tree)     |
                     +-----------------------------------+
                                       |
            +--------------------------+--------------------------+
            |                          |                          |
            v                          v                          v
+-----------------------+  +-----------------------+  +-----------------------+
|  Sigil::Filter::AST   |  |  Sigil::Flow::Tracker |  |  Sigil::Stats::Heavy  |
|  Boolean Filter Eval  |  |  TCP Stream Reassembly|  |  Entropy & Top Talkers|
+-----------------------+  +-----------------------+  +-----------------------+
            |                          |                          |
            +--------------------------+--------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |     Sigil::Export Subsystem       |
                     | Columnar / NDJSON / HexDump / CSV |
                     +-----------------------------------+
```

---

## Directory Structure

```
sigil/
├── META6.json                     # Raku package manifest and module dependencies
├── bin/                           # Command-line tools
│   ├── sigil                      # Primary multi-command CLI entrypoint
│   ├── sigil-dissect              # Dedicated packet dissector and inspector
│   ├── sigil-entropy              # Streaming Shannon entropy calculator
│   ├── sigil-filter               # High-speed packet filter evaluation tool
│   ├── sigil-flow                 # TCP stream reassembly and flow session extractor
│   └── sigil-pcapng               # PCAPNG block-structured file parser
├── lib/Sigil/                     # Core Raku implementation
│   ├── Types.rakumod              # Protocol enums, typed subsets, address wrappers
│   ├── Exception.rakumod          # Diagnostic exception hierarchy
│   ├── Core/
│   │   ├── Buffer.rakumod         # Zero-copy BufferCursor with mark/rewind
│   │   ├── Field.rakumod          # Structured field descriptors and formatters
│   │   ├── Checksum.rakumod       # RFC 1071 internet checksum, CRC32, Adler32
│   │   ├── Layer.rakumod          # Protocol layer abstraction and field container
│   │   ├── Packet.rakumod         # Multi-layer packet model and tree traversals
│   │   ├── Registry.rakumod       # Dynamic dissector registration and dispatch
│   │   └── Dissector.rakumod      # Recursive pipeline driver across L2-L7
│   ├── Grammar/
│   │   └── Common.rakumod         # ABNF lexical tokens and address grammars
│   ├── Dissector/
│   │   ├── L2/                    # Ethernet II, 802.1Q, 802.1ad, ARP, LLDP
│   │   ├── L3/                    # IPv4, IPv6, ICMPv4, ICMPv6, IGMP
│   │   ├── L4/                    # TCP, UDP, SCTP, QUIC
│   │   └── L7/                    # DNS, DNSSEC, DHCP, NTP, HTTP, TLS, WS, MQTT,
│   │                              # Redis, BGP-4, SSH, Syslog
│   ├── Filter/
│   │   ├── Grammar.rakumod        # BPF-like filter grammar
│   │   ├── Actions.rakumod        # AST semantic actions and node construction
│   │   ├── AST.rakumod            # Abstract syntax tree nodes with short-circuit eval
│   │   └── Compiler.rakumod       # Filter compiler and predicate optimizer
│   ├── Flow/
│   │   ├── Reassembly.rakumod     # RFC 9293 TCP sequence gap tracking and splicing
│   │   └── Tracker.rakumod        # Bi-directional flow state machine and metrics
│   ├── Stats/
│   │   ├── Entropy.rakumod        # Sliding-window Shannon entropy estimator
│   │   ├── HeavyHitters.rakumod   # Space-Saving streaming top-talker algorithm
│   │   └── Anomaly.rakumod        # Statistical threshold anomaly detector
│   ├── IO/
│   │   ├── PcapReader.rakumod     # Classic libpcap binary parser
│   │   ├── PcapWriter.rakumod     # Binary PCAP trace generator
│   │   └── PcapNg.rakumod         # Section Header and Enhanced Packet block parser
│   ├── Export/
│   │   ├── Formatter.rakumod      # Wireshark-style columnar table formatter
│   │   ├── JSON.rakumod           # Structured NDJSON serialisation engine
│   │   └── HexDump.rakumod        # ANSI colored hex dump with ASCII sidebar
│   ├── Capture/
│   │   ├── RingBuffer.rakumod     # Inter-process communication ring reader
│   │   ├── Offline.rakumod        # Offline trace replayer with timing emulation
│   │   └── Plugin.rakumod         # Dynamic plugin loader and dispatch hooks
│   └── CLI/
│       ├── Options.rakumod        # Strict command-line argument parser
│       └── Runner.rakumod         # CLI subcommand dispatcher and runner
├── capture/                       # High-performance C11 capture core
│   ├── include/                   # Public headers (ring, shm, pcap_fast)
│   ├── src/                       # Lockless ring, shm IPC, zero-copy mmap reader
│   ├── test/                      # Unit tests and multi-threaded stress harnesses
│   └── Makefile                   # Clang/GCC build specification
├── dashboard/                     # Asynchronous telemetry console
│   ├── sigil_dashboard/           # State models, curses UI, sparkline renderers
│   └── tests/                     # Python unit tests
├── docs/                          # Architecture and API documentation
│   ├── architecture/              # In-depth architectural specifications
│   ├── guides/                    # Getting started and custom dissector guides
│   └── api/                       # Subsystem module reference
├── scripts/                       # Developer verification scripts
│   ├── benchmark.raku             # Packet dissection and filter benchmark
│   ├── generate_fixtures.raku     # Synthetic multi-protocol PCAP generator
│   └── verify_no_em_dash.sh       # Static compliance enforcement tool
└── t/                             # Comprehensive test suite (45 test files)
```

---

## Performance Benchmarks

Microbenchmarks measured on Apple M-series hardware (64-bit ARM, 16GB RAM):

| Benchmark Component | Workload | Throughput | Latency |
| :--- | :--- | :--- | :--- |
| **C11 SPSC Ring Buffer** | Push/Pop 10M frames | **22.34 Million pkts/sec** | ~44 nanoseconds/pkt |
| **C11 Zero-Copy mmap PCAP**| Sequential trace scan | **14.80 Million pkts/sec** | ~67 nanoseconds/pkt |
| **Raku Buffer Cursor** | Mark, slice, rewind | **1.42 Million ops/sec** | ~704 nanoseconds/op |
| **Raku Filter AST** | Complex boolean predicates| **71,400 evals/sec** | ~14 microseconds/eval |
| **Raku L2-L4 Dissection** | Ethernet + IPv4 + TCP | **18,500 pkts/sec** | ~54 microseconds/pkt |
| **Raku L7 Deep Dissection** | HTTP/1.1 + Headers + URI | **8,200 pkts/sec** | ~121 microseconds/pkt |

---

## Quickstart

### Prerequisites

- **Raku**: Rakudo 2023.01 or later (`rakudo` package or via `rakubrew`)
- **C Compiler**: GCC 9+ or Clang 11+ with C11 support and POSIX threads
- **Python**: Python 3.11+ (standard library only, no pip dependencies required)

### Building the Project

```bash
# Clone the repository
git clone https://github.com/Aneesh495/sigil.git
cd sigil

# Compile the high-performance C capture core
cd capture
make all
cd ..

# Verify test suites across all subsystems
./scripts/verify_no_em_dash.sh
prove -e "raku -Ilib" -r t/
cd capture && make test && cd ..
cd dashboard && python3 -m unittest discover -s tests && cd ..
```

---

## CLI Usage Examples

### 1. Packet Dissection and Live Summary

Dissect a capture file and view Wireshark-style columnar output:

```bash
./bin/sigil dissect t/fixtures/golden_multi_protocol.pcap
```

Render detailed hierarchical protocol trees with hex dumps:

```bash
./bin/sigil dissect --verbose --hex t/fixtures/golden_multi_protocol.pcap
```

### 2. High-Speed Filter Queries

Filter packets matching specific boolean criteria:

```bash
# Filter HTTPS packets or DNS responses
./bin/sigil filter -f "tcp.port == 443 || dns.qr == 1" t/fixtures/golden_multi_protocol.pcap

# Export matching frames to NDJSON
./bin/sigil filter -f "ip.len > 100" --format json t/fixtures/golden_multi_protocol.pcap
```

### 3. TCP Stream Reassembly

Reconstruct bidirectional conversations and inspect reassembled payloads:

```bash
./bin/sigil flow --reassemble t/fixtures/golden_multi_protocol.pcap
```

### 4. Entropy and Security Anomaly Scanning

Scan a capture file for high-entropy payloads (encrypted tunnels, exfiltration) and security anomalies (SYN floods, port scans):

```bash
./bin/sigil entropy --threshold 7.2 t/fixtures/golden_multi_protocol.pcap
```

### 5. High-Throughput C Capture Engine

Run the C ingestion core with memory-mapped PCAP parsing:

```bash
./capture/build/sigil-capture -f t/fixtures/golden_multi_protocol.pcap -r /sigil_ring
```

---

## Documentation Index

Comprehensive documentation is available in the `docs/` tree:

- [System Architecture Overview](docs/architecture/overview.md)
- [Protocol Grammar DSL & Buffer Cursor](docs/architecture/grammar_dsl.md)
- [TCP Stream Reassembly Specification](docs/architecture/flow_reassembly.md)
- [BPF Filter Engine & AST Architecture](docs/architecture/filter_engine.md)
- [C Lockless Ingestion Core](docs/architecture/c_capture_core.md)
- [Getting Started Guide](docs/guides/getting_started.md)
- [Authoring Custom Dissectors & Plugins](docs/guides/custom_dissectors.md)
- [Subsystem API Reference](docs/api/reference.md)

---

## Running Test Suites

Sigil features exhaustive unit, integration, and fuzz testing:

```bash
# 1. Verify zero em dashes across the repository
./scripts/verify_no_em_dash.sh

# 2. Run all 45 Raku test files
prove -e "raku -Ilib" -r t/

# 3. Run C capture engine tests and microbenchmarks
cd capture
make clean && make test && make all
./build/sigil-capture -b
cd ..

# 4. Run Python dashboard state tests
cd dashboard
python3 -m unittest discover -s tests
cd ..
```

---

## Contributing & Development

Contributions to Sigil are welcome. When submitting changes:

1. Maintain documentation integrity.
2. Ensure all code passes static verification with `./scripts/verify_no_em_dash.sh`.
3. Add unit test coverage for new protocols in `t/`.
4. Follow the existing architectural patterns for dissectors and AST nodes.

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
