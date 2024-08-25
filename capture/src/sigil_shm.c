/*
 * sigil_shm.c - POSIX shared memory ring buffer implementation
 *
 * Implements low-latency inter-process ring buffer mapping for high-speed
 * packet delivery to userspace analytics workers.
 */

#include "sigil_shm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

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

int sigil_shm_create(sigil_shm_ctx_t *ctx, const char *shm_name, uint32_t capacity) {
    if (!ctx || !shm_name) return -1;

    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->shm_name, shm_name, sizeof(ctx->shm_name) - 1);
    ctx->is_creator = true;

    uint32_t pow2_cap = round_up_pow2(capacity);
    size_t slots_size = sizeof(sigil_packet_slot_t) * pow2_cap;
    ctx->total_size = sizeof(sigil_shm_header_t) + slots_size;

    /* Unlink any preexisting segment */
    shm_unlink(shm_name);

    ctx->fd = shm_open(shm_name, O_CREAT | O_RDWR | O_EXCL, 0666);
    if (ctx->fd < 0) {
        return -1;
    }

    if (ftruncate(ctx->fd, (off_t)ctx->total_size) != 0) {
        close(ctx->fd);
        shm_unlink(shm_name);
        return -1;
    }

    void *mapped = mmap(NULL, ctx->total_size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
    if (mapped == MAP_FAILED) {
        close(ctx->fd);
        shm_unlink(shm_name);
        return -1;
    }

    ctx->header = (sigil_shm_header_t *)mapped;
    ctx->slots = (sigil_packet_slot_t *)((uint8_t *)mapped + sizeof(sigil_shm_header_t));

    ctx->header->magic = SIGIL_MAGIC_IPC;
    ctx->header->capacity = pow2_cap;
    ctx->header->slot_size = sizeof(sigil_packet_slot_t);
    ctx->header->drop_count = 0;
    ctx->header->head = 0;
    ctx->header->tail = 0;

    return 0;
}

int sigil_shm_attach(sigil_shm_ctx_t *ctx, const char *shm_name) {
    if (!ctx || !shm_name) return -1;

    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->shm_name, shm_name, sizeof(ctx->shm_name) - 1);
    ctx->is_creator = false;

    ctx->fd = shm_open(shm_name, O_RDWR, 0666);
    if (ctx->fd < 0) {
        return -1;
    }

    /* Map header first to read capacity */
    void *header_map = mmap(NULL, sizeof(sigil_shm_header_t), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
    if (header_map == MAP_FAILED) {
        close(ctx->fd);
        return -1;
    }

    sigil_shm_header_t *temp_hdr = (sigil_shm_header_t *)header_map;
    if (temp_hdr->magic != SIGIL_MAGIC_IPC) {
        munmap(header_map, sizeof(sigil_shm_header_t));
        close(ctx->fd);
        return -1;
    }

    uint32_t capacity = temp_hdr->capacity;
    size_t full_size = sizeof(sigil_shm_header_t) + (sizeof(sigil_packet_slot_t) * capacity);
    munmap(header_map, sizeof(sigil_shm_header_t));

    void *mapped = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
    if (mapped == MAP_FAILED) {
        close(ctx->fd);
        return -1;
    }

    ctx->total_size = full_size;
    ctx->header = (sigil_shm_header_t *)mapped;
    ctx->slots = (sigil_packet_slot_t *)((uint8_t *)mapped + sizeof(sigil_shm_header_t));

    return 0;
}

void sigil_shm_close(sigil_shm_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->header && ctx->total_size > 0) {
        munmap(ctx->header, ctx->total_size);
        ctx->header = NULL;
        ctx->slots = NULL;
    }

    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    if (ctx->is_creator && ctx->shm_name[0] != '\0') {
        shm_unlink(ctx->shm_name);
    }
}

bool sigil_shm_push(sigil_shm_ctx_t *ctx, const uint8_t *data, uint16_t caplen, uint16_t wirelen, uint32_t ts_sec, uint32_t ts_usec) {
    if (!ctx || !ctx->header || !data) return false;

    uint64_t head = ctx->header->head;
    uint64_t tail = __atomic_load_n(&ctx->header->tail, __ATOMIC_ACQUIRE);
    uint32_t capacity = ctx->header->capacity;
    uint32_t mask = capacity - 1;

    if (head - tail >= capacity) {
        ctx->header->drop_count++;
        return false;
    }

    uint32_t idx = (uint32_t)(head & mask);
    sigil_packet_slot_t *slot = &ctx->slots[idx];

    slot->magic = SIGIL_MAGIC_IPC;
    slot->seq = (uint32_t)head;
    slot->ts_sec = ts_sec;
    slot->ts_usec = ts_usec;

    uint16_t copy_len = caplen > sizeof(slot->data) ? (uint16_t)sizeof(slot->data) : caplen;
    slot->caplen = copy_len;
    slot->wirelen = wirelen;
    memcpy(slot->data, data, copy_len);

    __atomic_store_n(&ctx->header->head, head + 1, __ATOMIC_RELEASE);
    return true;
}

bool sigil_shm_pop(sigil_shm_ctx_t *ctx, sigil_packet_slot_t *out_slot) {
    if (!ctx || !ctx->header || !out_slot) return false;

    uint64_t tail = ctx->header->tail;
    uint64_t head = __atomic_load_n(&ctx->header->head, __ATOMIC_ACQUIRE);
    uint32_t capacity = ctx->header->capacity;
    uint32_t mask = capacity - 1;

    if (tail >= head) {
        return false;
    }

    uint32_t idx = (uint32_t)(tail & mask);
    const sigil_packet_slot_t *slot = &ctx->slots[idx];

    memcpy(out_slot, slot, sizeof(sigil_packet_slot_t));
    __atomic_store_n(&ctx->header->tail, tail + 1, __ATOMIC_RELEASE);

    return true;
}
