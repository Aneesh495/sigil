/*
 * sigil_ring.h - Lockless single-producer single-consumer (SPSC) ring buffer
 *
 * Implements bounded-latency memory-ordered ring buffer with cacheline padding
 * to eliminate false sharing between capture thread and consumer.
 */

#ifndef SIGIL_RING_H
#define SIGIL_RING_H

#include "sigil_types.h"
#include <stdalign.h>

#define SIGIL_CACHELINE_SIZE 64

typedef struct sigil_ring {
    uint32_t capacity;      /* Power of two number of slots */
    uint32_t mask;          /* capacity - 1 */
    sigil_packet_slot_t *slots;

    /* Producer state (cache-line isolated) */
    alignas(SIGIL_CACHELINE_SIZE) volatile uint64_t head;
    uint64_t cached_tail;

    /* Consumer state (cache-line isolated) */
    alignas(SIGIL_CACHELINE_SIZE) volatile uint64_t tail;
    uint64_t cached_head;

    /* Telemetry */
    uint64_t push_count;
    uint64_t drop_count;
} sigil_ring_t;

/* Initialize SPSC ring buffer with given power-of-two slot count */
int sigil_ring_init(sigil_ring_t *ring, uint32_t capacity);

/* Destroy ring and free memory */
void sigil_ring_free(sigil_ring_t *ring);

/* Push packet into ring (producer only); returns true on success, false if full */
bool sigil_ring_push(sigil_ring_t *ring, const uint8_t *data, uint16_t caplen, uint16_t wirelen, uint32_t ts_sec, uint32_t ts_usec);

/* Pop packet from ring (consumer only); returns true on success, false if empty */
bool sigil_ring_pop(sigil_ring_t *ring, sigil_packet_slot_t *out_slot);

/* Number of items currently queued in ring */
uint32_t sigil_ring_count(const sigil_ring_t *ring);

/* Check if ring is empty */
bool sigil_ring_is_empty(const sigil_ring_t *ring);

#endif /* SIGIL_RING_H */
