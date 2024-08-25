/*
 * test_ring.c - Unit and stress tests for Sigil lockless SPSC ring buffer
 */

#include "sigil_ring.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#define STRESS_PACKETS 500000

typedef struct thread_arg {
    sigil_ring_t *ring;
    uint32_t count;
} thread_arg_t;

static void *producer_fn(void *arg) {
    thread_arg_t *t = (thread_arg_t *)arg;
    uint8_t payload[32];

    for (uint32_t i = 0; i < t->count; i++) {
        *(uint32_t *)payload = i;
        while (!sigil_ring_push(t->ring, payload, sizeof(payload), sizeof(payload), 100, i)) {
            /* Spin wait when ring is full */
        }
    }
    return NULL;
}

static void *consumer_fn(void *arg) {
    thread_arg_t *t = (thread_arg_t *)arg;
    sigil_packet_slot_t slot;
    uint32_t expected_seq = 0;

    while (expected_seq < t->count) {
        if (sigil_ring_pop(t->ring, &slot)) {
            uint32_t val = *(uint32_t *)slot.data;
            assert(val == expected_seq);
            expected_seq++;
        }
    }
    return NULL;
}

int main(void) {
    printf("Running Sigil Ring Unit Tests...\n");

    /* 1. Basic capacity and power-of-two rounding */
    sigil_ring_t ring;
    assert(sigil_ring_init(&ring, 100) == 0);
    assert(ring.capacity == 128); /* 100 rounds up to 128 */
    assert(sigil_ring_is_empty(&ring));
    assert(sigil_ring_count(&ring) == 0);

    /* 2. Pop on empty returns false */
    sigil_packet_slot_t slot;
    assert(!sigil_ring_pop(&ring, &slot));

    /* 3. Fill ring to capacity */
    uint8_t data[16] = "TEST_SLOT_DATA_";
    for (uint32_t i = 0; i < 128; i++) {
        assert(sigil_ring_push(&ring, data, sizeof(data), sizeof(data), 1, i));
    }
    assert(sigil_ring_count(&ring) == 128);

    /* 4. Overflow returns false */
    assert(!sigil_ring_push(&ring, data, sizeof(data), sizeof(data), 1, 999));
    assert(ring.drop_count == 1);

    /* 5. Drain ring and verify FIFO */
    for (uint32_t i = 0; i < 128; i++) {
        assert(sigil_ring_pop(&ring, &slot));
        assert(slot.ts_usec == i);
    }
    assert(sigil_ring_is_empty(&ring));
    sigil_ring_free(&ring);
    printf("  [PASS] Single-thread ring operations passed.\n");

    /* 6. Multi-threaded Producer-Consumer stress test */
    printf("Running Multi-threaded Ring Stress Test (%u packets)...\n", STRESS_PACKETS);
    assert(sigil_ring_init(&ring, 2048) == 0);

    thread_arg_t targ = { .ring = &ring, .count = STRESS_PACKETS };
    pthread_t prod, cons;

    pthread_create(&cons, NULL, consumer_fn, &targ);
    pthread_create(&prod, NULL, producer_fn, &targ);

    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    sigil_ring_free(&ring);
    printf("  [PASS] Multi-threaded SPSC stress test verified with 0 data corruptions.\n");

    printf("All Sigil Ring Tests Passed!\n");
    return 0;
}
