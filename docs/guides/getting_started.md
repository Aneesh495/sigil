# Getting Started with Sigil

This guide covers building, testing, and running the Sigil network telemetry engine.

## Prerequisites

- **Raku**: Rakudo Raku compiler (v2022.04 or newer).
- **C Compiler**: Clang or GCC with C11 support (`-std=c11`, POSIX threads).
- **Python**: Python 3.8+ (standard library curses for terminal dashboard).
- **Make / CMake**: GNU Make 3.81+ or CMake 3.16+.

## Installation & Compilation

### 1. Build the C Capture Engine
The C engine provides the high-performance SPSC ring buffer, mmap PCAP reader, and benchmark utility:

```bash
cd capture
make all
make test
```

Run the in-memory ring buffer throughput benchmark:
```bash
./build/sigil-capture -b
```

### 2. Verify Raku Dependencies & Modules
Sigil is self-contained and implemented with standard Raku grammar and networking libraries. Check module compilation:

```bash
raku -Ilib -c lib/Sigil/Core/Dissector.rakumod
```

### 3. Generate Golden Test PCAP Traces
Generate synthetic binary traces containing multi-layer protocols, TCP handshakes, DNS queries, and security anomalies:

```bash
raku scripts/generate_fixtures.raku
```

This creates:
- `t/fixtures/http_session.pcap`: Full TCP 3-way handshake and HTTP/1.1 request/response.
- `t/fixtures/dns_query.pcap`: RFC 1035 DNS A-record query.
- `t/fixtures/syn_flood.pcap`: Half-open SYN flood traffic pattern.

## Running the Test Suite

Execute the complete Raku test suite across core buffers, protocol grammars, flow reassembly, filter compilers, and exporters:

```bash
prove -e raku -r t/
```

Execute the Python dashboard test suite:
```bash
cd dashboard
python3 -m unittest discover -s tests
```

## CLI Usage Examples

### Dissecting Packet Traces
Print Wireshark-style one-line summaries:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap
```

Expand hierarchical protocol tree with complete field decoding:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap -V
```

### Applying BPF-Like Filter Expressions
Filter for destination port 80:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap -f "tcp.dstport == 80"
```

Filter for specific IP subnets and protocols:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap -f "ip.proto == 6 && ip.src in 192.168.1.0/24"
```

### Exporting Formats
Export to newline-delimited JSON (NDJSON) for SIEM ingestion:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap --format=ndjson
```

Export tabular telemetry to CSV:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap --format=csv
```

Print side-by-side hex and ASCII memory dumps:
```bash
./bin/sigil dissect -r t/fixtures/http_session.pcap --format=hex
```

### Tracking TCP/UDP Conversation Flows
Analyze bidirectional conversations, RTT, and stream reassembly:
```bash
./bin/sigil flow -r t/fixtures/http_session.pcap
```

### Statistical Telemetry & Anomaly Inspection
Aggregate packet rate, volume distributions, top talkers, and security alerts:
```bash
./bin/sigil stats -r t/fixtures/syn_flood.pcap
```

### Launching the Terminal User Interface (TUI)
Start the curses real-time dashboard:
```bash
python3 dashboard/run_dashboard.py
```
- Press `Tab` or keys `1`-`4` to switch views (Packets, Flows, Inspector, Telemetry).
- Use `Up`/`Down` (or `j`/`k`) to select packets for inspection.
- Press `Space` to pause or resume live capture.
- Press `q` to quit.
