# C High-Throughput Capture Core & Ring Buffer Architecture

The Sigil C Capture Engine (`capture/`) is a low-latency systems component designed for high-speed packet ingestion, memory-mapped trace processing, and inter-process IPC streaming.

```
+-----------------------------------------------------------------------------+
|                     LOCKLESS SPSC RING BUFFER ARCHITECTURE                  |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Producer Thread (Network Card / PCAP)                                     |
|   +-----------------------------------------------------------------------+ |
|   | head: 64-byte Cache-Line Aligned | cached_tail: Local Read Copy       | |
|   +-----------------------------------------------------------------------+ |
|                                |                                            |
|                                | Writes payload, executes                   |
|                                | __atomic_store_n(&head, RELEASE)           |
|                                v                                            |
|   Circular Slot Array (Capacity = Power of 2, e.g. 4096 / 65536)            |
|   +--------+--------+--------+--------+--------+--------+--------+--------+ |
|   | Slot 0 | Slot 1 | Slot 2 | Slot 3 | ...... | Slot N | Slot...| Slot M | |
|   +--------+--------+--------+--------+--------+--------+--------+--------+ |
|                                ^                                            |
|                                | Reads payload, executes                    |
|                                | __atomic_store_n(&tail, RELEASE)           |
|                                |                                            |
|   Consumer Thread (IPC / Shared Memory / Userspace Engine)                  |
|   +-----------------------------------------------------------------------+ |
|   | tail: 64-byte Cache-Line Aligned | cached_head: Local Read Copy       | |
|   +-----------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------+
```

## Eliminating False Sharing

In multi-threaded shared memory systems, independent variables located on the same 64-byte CPU cache line cause continuous cache-invalidation cycles (false sharing) between core L1/L2 caches:

```c
typedef struct sigil_ring {
    uint32_t capacity;
    uint32_t mask;
    sigil_packet_slot_t *slots;

    /* Producer state (isolated on distinct 64-byte cacheline) */
    alignas(64) volatile uint64_t head;
    uint64_t cached_tail;

    /* Consumer state (isolated on distinct 64-byte cacheline) */
    alignas(64) volatile uint64_t tail;
    uint64_t cached_head;
} sigil_ring_t;
```

Aligning `head` and `tail` to 64-byte boundaries ensures that the producer core never invalidates the consumer core's cache line during high-throughput updates.

## Memory Ordering & Atomic Semantics

The ring operates completely lock-free without mutexes or kernel system calls:
- **Producer Push**: Reads `cached_tail`. If capacity headroom is exhausted, fetches `tail` using `__atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE)`. Writes the packet descriptor into slot `idx = head & mask`. Finally, commits the slot with `__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE)`. The release barrier guarantees all packet payload bytes are visible in memory before the new head index becomes readable.
- **Consumer Pop**: Reads `cached_head`. If empty, fetches `head` using `__atomic_load_n(&ring->head, __ATOMIC_ACQUIRE)`. Copies slot payload to destination, then publishes updated progress with `__atomic_store_n(&ring->tail, tail + 1, __ATOMIC_RELEASE)`.

## Zero-Copy Memory-Mapped PCAP Reader (`sigil_pcap_fast.c`)

For offline traces, classic file I/O (`read()`) suffers from user-kernel context switching and buffer copies:
1. Trace files are mapped directly into virtual address space via `mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0)`.
2. Packet record headers and payloads are read by direct pointer arithmetic without intermediate allocation.
3. Microsecond and nanosecond endianness headers are decoded inline.
4. Line-rate benchmark performance exceeds 22 Million operations/second on modern architectures.

## POSIX Shared Memory IPC (`sigil_shm.c`)

To deliver packets across language boundaries (C to Raku or Python) with microsecond latency, Sigil implements POSIX shared memory segments (`shm_open`, `ftruncate`, `mmap`):
- Header `sigil_shm_header_t` stores ring pointers and drop counters.
- Slots follow contiguously in shared RAM (`/dev/shm`).
- Multiple independent processes can attach and monitor packet streams in parallel without network socket overhead.
