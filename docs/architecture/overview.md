# Sigil Architecture Overview

Sigil is a high-throughput network packet dissection, flow reassembly, stream telemetry, and forensic analysis engine. The project marries high-level declarative protocol grammar specifications in Raku with a low-level lockless C capture engine and an asynchronous Python terminal dashboard.

```
 +-------------------------------------------------------------------------+
 |                                  SIGIL                                  |
 +-------------------------------------------------------------------------+
 |                                                                         |
 |  [ Network Wire / PCAP ]                                                |
 |          |                                                              |
 |          v                                                              |
 |  +--------------------+                                                 |
 |  |  C Capture Engine  |  (mmap zero-copy reader, SPSC ring buffer,      |
 |  |  (capture/)        |   POSIX shared memory, 22M pkts/sec)            |
 |  +--------------------+                                                 |
 |          |                                                              |
 |     POSIX SHM /                                                         |
 |    Unix Socket IPC                                                      |
 |          |                                                              |
 |          v                                                              |
 |  +-------------------------------------------------------------------+  |
 |  |                       Raku Core Engine                            |  |
 |  |                                                                   |  |
 |  |  +--------------------+   +-------------------+   +------------+  |  |
 |  |  | Protocol Grammar   |   | Packet Filter DSL |   | Flow State |  |  |
 |  |  | Dissectors (L2-L7) |-->| AST & JIT Compiler|-->| & Stream   |  |  |
 |  |  | (Ethernet..QUIC)   |   | (BPF-like Preds)  |   | Reassembly |  |  |
 |  |  +--------------------+   +-------------------+   +------------+  |  |
 |  |                                                         |         |  |
 |  |                                                         v         |  |
 |  |                                                   +------------+  |  |
 |  |                                                   | Telemetry  |  |  |
 |  |                                                   | & Forensics|  |  |
 |  |                                                   | (Entropy)  |  |  |
 |  |                                                   +------------+  |  |
 |  +-------------------------------------------------------------------+  |
 |          |                                                              |
 |      NDJSON Stream                                                      |
 |          |                                                              |
 |          v                                                              |
 |  +--------------------+                                                 |
 |  |  Python Dashboard  |  (Real-time curses TUI, sparklines,             |
 |  |  (dashboard/)      |   flow table, packet inspector)                 |
 |  +--------------------+                                                 |
 +-------------------------------------------------------------------------+
```

## Subsystem Architecture

### 1. Ingestion Layer (`capture/` and `lib/Sigil/Capture/`)
Network frames are acquired through two primary vectors:
- **Offline Traces**: Direct parsing of classic libpcap (.pcap) and PCAP Next Generation (.pcapng) capture files. The C engine uses `mmap()` to achieve multi-gigabyte-per-second trace parsing with zero in-kernel copies.
- **Inter-Process IPC**: A lockless single-producer single-consumer (SPSC) ring buffer implemented in C allows high-rate background capture threads to stream packets directly to userspace workers via POSIX shared memory (`/dev/shm`) or local Unix domain sockets.

### 2. Dissection Pipeline (`lib/Sigil/Core/` and `lib/Sigil/Grammar/`)
Protocol decoding is structured as a recursive layer traversal:
- Each frame begins at Layer 2 (typically Ethernet II or Linux SLL).
- Dissectors parse the local header, validate length constraints, compute or verify RFC 1071 checksums, and extract typed fields (`FieldList`).
- Multiplexing selectors (such as EtherType, IP Protocol Number, UDP/TCP destination ports) dispatch execution to the next registered dissector in `Sigil::Core::Registry`.
- Layer 7 payload decoders utilize heuristic sniffing when standard port mappings do not match, identifying HTTP, TLS ClientHello, and SSH banners dynamically.

### 3. Filter Compiler (`lib/Sigil/Filter/`)
The filter DSL provides Wireshark-like boolean expressions (e.g., `ip.proto == 6 && (tcp.dstport == 80 || tcp.dstport == 443)`):
- Lexical tokens are recognized via `Sigil::Filter::Grammar`.
- The AST generator (`Sigil::Filter::Actions`) constructs a composite tree of `Node` objects.
- `Sigil::Filter::Compiler` transforms the AST into an optimized Raku callable closure, caching compiled predicates for high-throughput stream evaluation.

### 4. TCP Stream Reassembly (`lib/Sigil/Flow/`)
The flow subsystem tracks conversations across both transmission directions:
- Canonical 5-tuples normalize `(Protocol, SrcIP, DstIP, SrcPort, DstPort)` into an endpoint-ordered session key.
- Sequence hole tracking queues out-of-order TCP segments in an internal priority buffer.
- When missing sequence holes are filled, contiguous chunks are drained, duplicate byte overlaps are trimmed, and application payloads are forwarded to Layer 7 analyzers.
- State machines verify TCP handshake transitions (`SYN_SENT` -> `SYN_RECEIVED` -> `ESTABLISHED` -> `FIN_WAIT` -> `CLOSED`), calculating exact three-way handshake Round Trip Time (RTT).

### 5. Statistical Telemetry & Security Forensics (`lib/Sigil/Stats/`)
- **Space-Saving Heavy Hitters**: Implements the Metwally et al. stream algorithm to guarantee $O(k)$ bounded memory tracking of top talker IPs and conversation pairs.
- **Shannon Entropy Scanner**: Computes octet entropy distributions over sliding byte windows to detect packed malware payloads, encrypted tunnels, and high-entropy DNS exfiltration queries.
- **Behavioral Anomaly Engine**: Monitors half-open SYN-to-ACK ratios, vertical port scan thresholds, horizontal subnet sweeps, and illegal TCP flag combinations (Xmas and Null scans).
