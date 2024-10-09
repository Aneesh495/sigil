# TCP Stream Reassembly & Flow State Engine

Sigil implements bidirectional stream tracking, RFC 793/9293 state machine modeling, and sliding-window byte reassembly.

```
+-----------------------------------------------------------------------------+
|                      TCP STREAM REASSEMBLY PIPELINE                         |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Client                                                        Server      |
|     |                                                              |        |
|     |  Packet #1: SYN (seq = 1000)                                 |        |
|     |------------------------------------------------------------->|        |
|     |  State: SYN_SENT                                             |        |
|     |                                                              |        |
|     |  Packet #2: SYN+ACK (seq = 5000, ack = 1001)                 |        |
|     |<-------------------------------------------------------------|        |
|     |  State: SYN_RECEIVED | RTT = (t2 - t1)                       |        |
|     |                                                              |        |
|     |  Packet #3: ACK (seq = 1001, ack = 5001)                     |        |
|     |------------------------------------------------------------->|        |
|     |  State: ESTABLISHED                                          |        |
|                                                                             |
|   OUT-OF-ORDER DATA REASSEMBLY:                                             |
|                                                                             |
|   Expected next_seq = 1001                                                  |
|                                                                             |
|   1. Ingest Segment 2 (seq 1051..1100) -> Hole detected (1001..1050)        |
|      Enqueued in sorted pending priority buffer.                            |
|                                                                             |
|   2. Ingest Segment 1 (seq 1001..1050) -> Contiguous with next_seq!         |
|      - Flushes Segment 1 immediately (1001..1050)                           |
|      - Drains queued Segment 2 (1051..1100)                                 |
|      - next_seq advanced to 1101                                            |
|      - Entire contiguous 100-byte buffer delivered to Layer 7 dissector     |
|                                                                             |
|   3. Duplicate Retransmission (seq 1020..1060):                             |
|      - Redundant prefix (1020..1050) detected and trimmed                   |
|      - Redundant suffix ignored                                             |
|      - Zero payload duplication delivered upstream                          |
+-----------------------------------------------------------------------------+
```

## Canonical Direction Normalization

Network taps frequently capture packets in mixed directions. Sigil unifies communication into a single session key using lexical endpoint sorting:

```raku
my $ep1 = sprintf("%s:%d", $src_ip, $src_port);
my $ep2 = sprintf("%s:%d", $dst_ip, $dst_port);
my ($first, $second) = ($ep1 le $ep2) ?? ($ep1, $ep2) !! ($ep2, $ep1);
my $canonical_id = sprintf("%s %s <-> %s", $proto, $first, $second);
```

Regardless of whether packet A->B or B->A is processed first, both map to the exact same `Sigil::Flow::Session` container. Directional counters (`c2s_packets`, `s2c_packets`, `c2s_bytes`, `s2c_bytes`) track client and server volume independently.

## Sequence Hole Queuing & Overlap Trimming

`Sigil::Flow::TCPStream` manages an ordered list of non-contiguous payload fragments:
- **In-Order Arrival**: When segment sequence equals `next_seq`, payload is immediately appended to the flushed list, `next_seq` is advanced, and the pending queue is drained.
- **Hole Detection**: When segment sequence exceeds `next_seq`, the fragment is inserted into a sorted queue. A memory limit (default 1 MB per stream) protects against denial-of-service memory exhaustion attacks.
- **Overlapping Retransmission**: When segment sequence is less than `next_seq`, the overlap size is calculated (`$overlap = $next_seq - $seq`). If the segment contains new trailing data beyond the overlap, the redundant prefix is stripped via `.subbuf($overlap)` and the remaining suffix is ingested.

## Session Aging & Garbage Collection

`Sigil::Flow::Tracker` performs sweep passes to evict stale connections:
- Active TCP connections: 300 second idle timeout
- Active UDP pseudo-sessions: 60 second idle timeout
- Closed/Reset TCP connections: 10 second teardown grace window
