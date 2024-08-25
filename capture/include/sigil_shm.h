/*
 * sigil_shm.h - POSIX shared memory ring buffer IPC
 *
 * Implements low-latency inter-process ring buffer mapping for high-speed
 * packet delivery to userspace analytics workers.
 */

#ifndef SIGIL_SHM_H
#define SIGIL_SHM_H

#include "sigil_types.h"

typedef struct sigil_shm_ctx {
    char shm_name[128];
    int fd;
    size_t total_size;
    sigil_shm_header_t *header;
    sigil_packet_slot_t *slots;
    bool is_creator;
} sigil_shm_ctx_t;

/* Create and initialize shared memory ring (producer side) */
int sigil_shm_create(sigil_shm_ctx_t *ctx, const char *shm_name, uint32_t capacity);

/* Attach to existing shared memory ring (consumer side) */
int sigil_shm_attach(sigil_shm_ctx_t *ctx, const char *shm_name);

/* Detach and optionally unlink shared memory */
void sigil_shm_close(sigil_shm_ctx_t *ctx);

/* Producer: push packet into shared memory ring */
bool sigil_shm_push(sigil_shm_ctx_t *ctx, const uint8_t *data, uint16_t caplen, uint16_t wirelen, uint32_t ts_sec, uint32_t ts_usec);

/* Consumer: pop packet from shared memory ring */
bool sigil_shm_pop(sigil_shm_ctx_t *ctx, sigil_packet_slot_t *out_slot);

#endif /* SIGIL_SHM_H */
