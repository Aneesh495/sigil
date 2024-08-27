/*
 * sigil_capture.h - High-throughput multi-threaded capture engine orchestrator
 *
 * Coordinates ring buffers, trace reader threads, and IPC streaming workers.
 */

#ifndef SIGIL_CAPTURE_H
#define SIGIL_CAPTURE_H

#include "sigil_ring.h"
#include "sigil_shm.h"
#include "sigil_pcap_fast.h"
#include <pthread.h>

typedef struct sigil_engine {
    sigil_ring_t ring;
    sigil_shm_ctx_t shm;
    bool use_shm;
    const char *shm_name;
    const char *pcap_file;
    volatile bool running;
    pthread_t worker_thread;
    uint64_t total_captured;
    uint64_t total_dropped;
} sigil_engine_t;

int sigil_engine_init(sigil_engine_t *eng, const char *pcap_file, const char *shm_name, uint32_t ring_capacity);
int sigil_engine_start(sigil_engine_t *eng);
void sigil_engine_stop(sigil_engine_t *eng);
void sigil_engine_destroy(sigil_engine_t *eng);

#endif /* SIGIL_CAPTURE_H */
