# Sigil API Reference

This document provides a technical reference of classes, roles, and types across the Sigil subsystems.

---

## 1. Core Subsystem (`Sigil::Core`)

### `Sigil::Core::Buffer`
Low-level cursor providing byte extraction, rollback checkpoints, and arbitrary-width bitfield reading.
- `new(Buf $raw, Int :$offset = 0)`: Initialize cursor over byte buffer.
- `read-uint8(--> Int)` / `read-u8()`: Read unsigned 8-bit integer.
- `read-uint16-be(--> Int)` / `read-u16()`: Read unsigned 16-bit integer (big-endian).
- `read-uint16-le(--> Int)` / `read-u16-le()`: Read unsigned 16-bit integer (little-endian).
- `read-uint32-be(--> Int)` / `read-u32()`: Read unsigned 32-bit integer (big-endian).
- `read-uint32-le(--> Int)` / `read-u32-le()`: Read unsigned 32-bit integer (little-endian).
- `read-uint64-be(--> Int)` / `read-u64()`: Read unsigned 64-bit integer (big-endian).
- `read-bytes(Int $count --> Buf)`: Read slice of length `$count`.
- `read-remaining(--> Buf)`: Read all bytes from current cursor to buffer end.
- `read-bits(Int $count --> Int)`: Extract arbitrary bitfield (1 to 32 bits) across byte boundaries.
- `checkpoint(--> Int)`: Push current offset and bit registers onto rollback stack.
- `rollback()`: Restore cursor state to most recent checkpoint.
- `commit-checkpoint()`: Discard most recent checkpoint.
- `remaining(--> Int)`: Available unconsumed bytes.
- `at-eof(--> Bool)`: Whether cursor has reached end of buffer.

### `Sigil::Core::Layer`
Represents an individual decoded protocol header, its fields, and encapsulated payload.
- `has Str $.name`: Protocol name (e.g. "IPv4", "TCP", "HTTP").
- `has Str $.display-name`: Human-readable summary title.
- `has Int $.header-length`: Length of protocol header in bytes.
- `has Int $.payload-length`: Length of encapsulated payload in bytes.
- `has Buf $.raw-header`: Sliced header wire bytes.
- `has Buf $.raw-payload`: Sliced payload wire bytes.
- `has FieldList $.fields`: Ordered list of decoded fields.
- `has DissectionStatus $.status`: Parsing outcome (`STATUS_OK`, `STATUS_TRUNCATED`, `STATUS_MALFORMED`, `STATUS_CHECKSUM_MISMATCH`).
- `val(Str $key)`: Deep field lookup by key (e.g. `tcp.dstport`).
- `to-hash(--> Hash)`: Structured dictionary representation for JSON export.
- `to-tree-str(Int $indent --> Str)`: Hierarchical multi-line tree formatter.

### `Sigil::Core::Packet`
Multi-layer container representing a physical frame captured from network or trace file.
- `has Int $.packet-id`: Monotonic capture index.
- `has Num $.timestamp`: Fractional UNIX epoch seconds.
- `has Int $.wire-length`: Total length transmitted on physical wire.
- `has Int $.capture-length`: Bytes captured in buffer.
- `has Buf $.raw`: Raw wire octets.
- `push-layer(Layer $layer)`: Push newly decoded protocol layer onto stack.
- `layer(Str $proto-name --> Layer)`: Find decoded layer by protocol name.
- `has-layer(Str $proto-name --> Bool)`: Check whether protocol exists in stack.
- `highest-layer(--> Layer)`: Outermost decoded application or transport layer.
- `val(Str $key)`: Deep field lookup across all layers in stack.
- `summary(--> Str)`: Wireshark-style one-line summary.
- `to-tree-str(--> Str)`: Complete multi-layer tree representation.
- `hex-dump(Int :$width = 16 --> Str)`: Side-by-side hex and ASCII dump.
- `to-hash(--> Hash)`: Full packet JSON dictionary.

---

## 2. Filter Subsystem (`Sigil::Filter`)

### `Sigil::Filter::Compiler`
Compiles text filter queries into optimized boolean evaluator closures.
- `compile(Str $expr --> Sub)`: Parses query and returns executable `sub (Sigil::Core::Packet --> Bool)`.
- `clear-cache()`: Purges cached compiled filter predicates.

### `Sigil::Filter::Engine`
Runtime stream filter evaluator with telemetry accounting.
- `set-filter(Str $expr)`: Update active filter predicate.
- `matches(Sigil::Core::Packet $pkt --> Bool)`: Evaluate packet against filter.
- `filter-list(@packets --> List)`: Filter array of packets in memory.
- `stats(--> Hash)`: Evaluation counters, match counts, match percentage.

---

## 3. Flow Subsystem (`Sigil::Flow`)

### `Sigil::Flow::Key`
Normalized bidirectional conversation 5-tuple identifier.
- `from-packet(Packet $pkt --> Key)`: Factory method extracting endpoints from packet.
- `canonical-id(--> Str)`: Direction-invariant session string representation.
- `is-forward(Str $ip, Int $port --> Bool)`: Checks if packet aligns with session initiator.
- `reverse(--> Key)`: Swaps source and destination endpoints.

### `Sigil::Flow::TCPStream`
Sliding window out-of-order segment reassembly engine.
- `init-syn(Int $isn)`: Initialize stream with Initial Sequence Number.
- `add-segment(Int $seq, Buf $payload --> Buf)`: Ingests segment, fills holes, trims overlaps, and flushes contiguous bytes.
- `pending-chunks(--> Int)`: Number of out-of-order fragments buffered.
- `bytes-delivered(--> Int)`: Contiguous bytes delivered to upper layers.
- `retransmitted-bytes(--> Int)`: Redundant duplicate bytes stripped.

### `Sigil::Flow::Tracker`
Central conversation table and stream reassembly orchestrator.
- `process(Packet $pkt, Num $ts = 0e0 --> Session)`: Ingest packet into flow session.
- `purge-idle(Num $now = 0e0 --> Int)`: Garbage-collect aged-out and closed connections.
- `active-count(--> Int)`: Number of currently monitored flows.
- `active-sessions(--> List)`: List of all active sessions.

---

## 4. Telemetry & Forensics Subsystem (`Sigil::Stats`)

### `Sigil::Stats::TopTalkers`
Space-Saving heavy hitters stream algorithm.
- `observe(Str $key, Int $weight = 1)`: Record event weight for endpoint key.
- `top(Int $n = 10 --> List)`: Retrieve top-N keys with bounded error counts.
- `summary(Int $n = 10 --> Str)`: Formatted ASCII table.

### `Sigil::Stats::Entropy`
Shannon information entropy and payload randomness analysis.
- `shannon-entropy(Buf $data --> Num)`: Calculates entropy in bits/symbol (0.0 to 8.0).
- `string-entropy(Str $text --> Num)`: Computes entropy for text strings.
- `sliding-window-entropy(Buf $data, Int $window, Int $step --> List)`: Sliding window analysis.
- `chi-squared(Buf $data --> Num)`: Goodness-of-fit test against uniform distribution.
- `classify-randomness(Num $entropy --> Str)`: Heuristic payload classifier.

### `Sigil::Stats::Anomaly`
Real-time security and behavioral anomaly detector.
- `inspect(Packet $pkt, Num $ts = 0e0 --> List)`: Scans frame for port scans, SYN floods, Xmas/Null scans, and DNS tunneling.
- `alert-count(--> Int)`: Total detected anomalies.
- `alerts(--> List)`: Array of security alert records.
