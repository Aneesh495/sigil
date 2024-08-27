/*
 * sigil_capture.c - High-throughput multi-threaded capture engine implementation
 *
 * Coordinates ring buffers, trace reader threads, and IPC streaming workers.
 */

#include "sigil_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *capture_worker(void *arg) {
    sigil_engine_t *eng = (sigil_engine_t *)arg;
    if (!eng || !eng->pcap_file) return NULL;

    sigil_pcap_ctx_t pcap;
    if (sigil_pcap_open(&pcap, eng->pcap_file) != 0) {
        fprintf(stderr, "[Sigil-C] Error: Failed to open PCAP file '%s'\n", eng->pcap_file);
        eng->running = false;
        return NULL;
    }

    const uint8_t *data;
    uint16_t caplen, wirelen;
    uint32_t sec, usec;

    while (eng->running && sigil_pcap_next(&pcap, &data, &caplen, &wirelen, &sec, &usec)) {
        bool ok = sigil_ring_push(&eng->ring, data, caplen, wirelen, sec, usec);
        if (eng->use_shm) {
            sigil_shm_push(&eng->shm, data, caplen, wirelen, sec, usec);
        }

        if (ok) {
            eng->total_captured++;
        } else {
            eng->total_dropped++;
        }
    }

    sigil_pcap_close(&pcap);
    eng->running = false;
    return NULL;
}

int sigil_engine_init(sigil_engine_t *eng, const char *pcap_file, const char *shm_name, uint32_t ring_capacity) {
    if (!eng) return -1;
    memset(eng, 0, sizeof(*eng));

    eng->pcap_file = pcap_file;
    eng->shm_name = shm_name;
    eng->use_shm = (shm_name != NULL);

    if (sigil_ring_init(&eng->ring, ring_capacity) != 0) {
        return -1;
    }

    if (eng->use_shm) {
        if (sigil_shm_create(&eng->shm, shm_name, ring_capacity) != 0) {
            sigil_ring_free(&eng->ring);
            return -1;
        }
    }

    return 0;
}

int sigil_engine_start(sigil_engine_t *eng) {
    if (!eng) return -1;
    eng->running = true;
    if (pthread_create(&eng->worker_thread, NULL, capture_worker, eng) != 0) {
        eng->running = false;
        return -1;
    }
    return 0;
}

void sigil_engine_stop(sigil_engine_t *eng) {
    if (!eng || !eng->running) return;
    eng->running = false;
    pthread_join(eng->worker_thread, NULL);
}

void sigil_engine_destroy(sigil_engine_t *eng) {
    if (!eng) return;
    if (eng->running) {
        sigil_engine_stop(eng);
    }
    sigil_ring_free(&eng->ring);
    if (eng->use_shm) {
        sigil_shm_close(&eng->shm);
    }
}
