/*
 * sigil_types.h - Core type definitions and packet descriptors for Sigil C capture engine
 *
 * Provides shared memory layouts, ring buffer slot descriptors, and endian-safe
 * network header abstractions.
 */

#ifndef SIGIL_TYPES_H
#define SIGIL_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SIGIL_MAGIC_IPC         0x5349474CU /* 'SIGL' */
#define SIGIL_DEFAULT_SNAPLEN   65535
#define SIGIL_RING_DEFAULT_SLOTS 4096
#define SIGIL_SHM_NAME_DEFAULT  "/sigil_ring_shm"

#pragma pack(push, 1)

/* Packet descriptor stored within each ring buffer slot */
typedef struct sigil_packet_slot {
    uint32_t magic;         /* SIGIL_MAGIC_IPC */
    uint32_t seq;           /* Monotonic sequence number */
    uint32_t ts_sec;        /* Capture epoch seconds */
    uint32_t ts_usec;       /* Capture microseconds */
    uint16_t caplen;        /* Captured length in bytes */
    uint16_t wirelen;       /* Length on physical wire */
    uint8_t  data[2048];    /* Packet raw buffer */
} sigil_packet_slot_t;

#pragma pack(pop)

/* Header for POSIX shared memory ring (8-byte aligned for lockless atomics) */
typedef struct sigil_shm_header {
    uint32_t magic;         /* SIGIL_MAGIC_IPC */
    uint32_t capacity;      /* Number of slots (must be power of two) */
    uint32_t slot_size;     /* sizeof(sigil_packet_slot_t) */
    uint32_t drop_count;    /* Total packets dropped due to ring full */
    volatile uint64_t head; /* Producer write head index */
    volatile uint64_t tail; /* Consumer read tail index */
} sigil_shm_header_t;

#endif /* SIGIL_TYPES_H */
