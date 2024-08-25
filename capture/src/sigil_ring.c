/*
 * sigil_ring.c - Lockless single-producer single-consumer (SPSC) ring implementation
 *
 * Implements bounded-latency memory-ordered ring buffer with cacheline padding
 * to eliminate false sharing between capture thread and consumer.
 */

#include "sigil_ring.h"
#include <stdlib.h>
#include <string.h>

/* Round up integer to next power of two */
static uint32_t round_up_pow2(uint32_t v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v < 2 ? 2 : v;
}

int sigil_ring_init(sigil_ring_t *ring, uint32_t capacity) {
    if (!ring) return -1;

    uint32_t pow2_cap = round_up_pow2(capacity);
    ring->capacity = pow2_cap;
    ring->mask = pow2_cap - 1;
    ring->head = 0;
    ring->cached_tail = 0;
    ring->tail = 0;
    ring->cached_head = 0;
    ring->push_count = 0;
    ring->drop_count = 0;

    size_t total_size = sizeof(sigil_packet_slot_t) * pow2_cap;
    ring->slots = (sigil_packet_slot_t *)malloc(total_size);
    if (!ring->slots) {
        return -1;
    }

    memset(ring->slots, 0, total_size);
    return 0;
}

void sigil_ring_free(sigil_ring_t *ring) {
    if (ring && ring->slots) {
        free(ring->slots);
        ring->slots = NULL;
    }
}

bool sigil_ring_push(sigil_ring_t *ring, const uint8_t *data, uint16_t caplen, uint16_t wirelen, uint32_t ts_sec, uint32_t ts_usec) {
    if (!ring || !data) return false;

    uint64_t head = ring->head;
    uint64_t tail = ring->cached_tail;

    if (head - tail >= ring->capacity) {
        /* Refresh cached tail from consumer */
        tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
        ring->cached_tail = tail;

        if (head - tail >= ring->capacity) {
            /* Ring is full: drop packet and record counter */
            ring->drop_count++;
            return false;
        }
    }

    uint32_t idx = (uint32_t)(head & ring->mask);
    sigil_packet_slot_t *slot = &ring->slots[idx];

    slot->magic = SIGIL_MAGIC_IPC;
    slot->seq = (uint32_t)head;
    slot->ts_sec = ts_sec;
    slot->ts_usec = ts_usec;

    uint16_t copy_len = caplen > sizeof(slot->data) ? (uint16_t)sizeof(slot->data) : caplen;
    slot->caplen = copy_len;
    slot->wirelen = wirelen;
    memcpy(slot->data, data, copy_len);

    /* Release memory fence ensuring slot payload is written before head is updated */
    __atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
    ring->push_count++;

    return true;
}

bool sigil_ring_pop(sigil_ring_t *ring, sigil_packet_slot_t *out_slot) {
    if (!ring || !out_slot) return false;

    uint64_t tail = ring->tail;
    uint64_t head = ring->cached_head;

    if (tail >= head) {
        /* Refresh cached head from producer */
        head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
        ring->cached_head = head;

        if (tail >= head) {
            /* Ring is empty */
            return false;
        }
    }

    uint32_t idx = (uint32_t)(tail & ring->mask);
    const sigil_packet_slot_t *slot = &ring->slots[idx];

    memcpy(out_slot, slot, sizeof(sigil_packet_slot_t));

    /* Release memory fence updating consumer tail */
    __atomic_store_n(&ring->tail, tail + 1, __ATOMIC_RELEASE);

    return true;
}

uint32_t sigil_ring_count(const sigil_ring_t *ring) {
    if (!ring) return 0;
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
    return (uint32_t)(head >= tail ? (head - tail) : 0);
}

bool sigil_ring_is_empty(const sigil_ring_t *ring) {
    return sigil_ring_count(ring) == 0;
}
