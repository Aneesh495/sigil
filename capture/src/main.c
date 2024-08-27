/*
 * main.c - Sigil high-performance C capture engine CLI
 *
 * Provides benchmark harness and background ring buffer daemon for network traces.
 */

#include "sigil_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -r <file>      Read packets from PCAP trace file\n");
    printf("  -s <shm_name>  Enable POSIX shared memory ring (e.g. /sigil_ring)\n");
    printf("  -c <capacity>  Ring buffer slot capacity (default: 4096)\n");
    printf("  -b             Run fast in-memory throughput benchmark\n");
    printf("  -h             Show this help message\n");
}

int main(int argc, char **argv) {
    const char *pcap_file = NULL;
    const char *shm_name = NULL;
    uint32_t capacity = SIGIL_RING_DEFAULT_SLOTS;
    bool benchmark = false;

    int opt;
    while ((opt = getopt(argc, argv, "r:s:c:bh")) != -1) {
        switch (opt) {
            case 'r':
                pcap_file = optarg;
                break;
            case 's':
                shm_name = optarg;
                break;
            case 'c':
                capacity = (uint32_t)atoi(optarg);
                break;
            case 'b':
                benchmark = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (benchmark) {
        printf("=== SIGIL C SPSC RING BUFFER BENCHMARK ===\n");
        sigil_ring_t ring;
        if (sigil_ring_init(&ring, 65536) != 0) {
            fprintf(stderr, "Failed to initialize benchmark ring\n");
            return 1;
        }

        uint8_t dummy_pkt[64];
        memset(dummy_pkt, 0xAA, sizeof(dummy_pkt));

        const uint32_t iterations = 10000000;
        printf("Executing %u ring push/pop operations...\n", iterations);

        struct timespec t_start, t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_start);

        sigil_packet_slot_t slot;
        for (uint32_t i = 0; i < iterations; i++) {
            sigil_ring_push(&ring, dummy_pkt, sizeof(dummy_pkt), sizeof(dummy_pkt), 1000, 0);
            sigil_ring_pop(&ring, &slot);
        }

        clock_gettime(CLOCK_MONOTONIC, &t_end);
        double elapsed = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
        double mpps = (iterations / elapsed) / 1e6;

        printf("Completed %u operations in %.4f sec (%.2f Million ops/sec)\n", iterations, elapsed, mpps);
        sigil_ring_free(&ring);
        return 0;
    }

    if (!pcap_file) {
        printf("Sigil C Capture Engine ready. Specify -r <trace.pcap> or -b for benchmark.\n");
        return 0;
    }

    printf("[Sigil-C] Initializing engine with trace '%s', capacity=%u\n", pcap_file, capacity);
    sigil_engine_t eng;
    if (sigil_engine_init(&eng, pcap_file, shm_name, capacity) != 0) {
        fprintf(stderr, "[Sigil-C] Failed to initialize engine\n");
        return 1;
    }

    sigil_engine_start(&eng);

    while (eng.running) {
        usleep(10000);
    }

    sigil_engine_destroy(&eng);
    printf("[Sigil-C] Ingest complete: %llu packets captured, %llu dropped.\n",
        (unsigned long long)eng.total_captured, (unsigned long long)eng.total_dropped);

    return 0;
}
