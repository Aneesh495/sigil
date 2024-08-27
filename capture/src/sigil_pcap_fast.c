/*
 * sigil_pcap_fast.c - Memory-mapped zero-copy PCAP reader implementation
 *
 * Provides line-rate packet parsing across big-endian, little-endian,
 * microsecond, and nanosecond capture files.
 */

#include "sigil_pcap_fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PCAP_BE_MICRO 0xA1B2C3D4U
#define PCAP_LE_MICRO 0xD4C3B2A1U
#define PCAP_BE_NANO  0xA1B23C4DU
#define PCAP_LE_NANO  0x4D3CB2A1U

static inline uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

int sigil_pcap_open(sigil_pcap_ctx_t *ctx, const char *filepath) {
    if (!ctx || !filepath) return -1;

    memset(ctx, 0, sizeof(*ctx));

    ctx->fd = open(filepath, O_RDONLY);
    if (ctx->fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(ctx->fd, &st) != 0 || st.st_size < 24) {
        close(ctx->fd);
        return -1;
    }

    ctx->file_size = (size_t)st.st_size;
    void *map = mmap(NULL, ctx->file_size, PROT_READ, MAP_SHARED, ctx->fd, 0);
    if (map == MAP_FAILED) {
        close(ctx->fd);
        return -1;
    }

    ctx->mapped = (const uint8_t *)map;
    ctx->offset = 0;

    /* Parse 24-byte global header */
    uint32_t raw_magic = read_u32_be(ctx->mapped);

    if (raw_magic == PCAP_BE_MICRO) {
        ctx->is_little_endian = false;
        ctx->is_nanosecond = false;
    } else if (raw_magic == PCAP_LE_MICRO) {
        ctx->is_little_endian = true;
        ctx->is_nanosecond = false;
    } else if (raw_magic == PCAP_BE_NANO) {
        ctx->is_little_endian = false;
        ctx->is_nanosecond = true;
    } else if (raw_magic == PCAP_LE_NANO) {
        ctx->is_little_endian = true;
        ctx->is_nanosecond = true;
    } else {
        /* Unsupported or corrupt magic */
        munmap(map, ctx->file_size);
        close(ctx->fd);
        return -1;
    }

    if (ctx->is_little_endian) {
        ctx->snaplen = read_u32_le(ctx->mapped + 16);
        ctx->linktype = read_u32_le(ctx->mapped + 20);
    } else {
        ctx->snaplen = read_u32_be(ctx->mapped + 16);
        ctx->linktype = read_u32_be(ctx->mapped + 20);
    }

    ctx->offset = 24;
    ctx->packet_count = 0;

    return 0;
}

void sigil_pcap_close(sigil_pcap_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->mapped && ctx->file_size > 0) {
        munmap((void *)ctx->mapped, ctx->file_size);
        ctx->mapped = NULL;
    }

    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
}

bool sigil_pcap_next(sigil_pcap_ctx_t *ctx, const uint8_t **out_data, uint16_t *out_caplen, uint16_t *out_wirelen, uint32_t *out_sec, uint32_t *out_usec) {
    if (!ctx || !ctx->mapped) return false;

    if (ctx->offset + 16 > ctx->file_size) {
        return false;
    }

    const uint8_t *rec = ctx->mapped + ctx->offset;
    uint32_t sec, usec, incl_len, orig_len;

    if (ctx->is_little_endian) {
        sec = read_u32_le(rec);
        usec = read_u32_le(rec + 4);
        incl_len = read_u32_le(rec + 8);
        orig_len = read_u32_le(rec + 12);
    } else {
        sec = read_u32_be(rec);
        usec = read_u32_be(rec + 4);
        incl_len = read_u32_be(rec + 8);
        orig_len = read_u32_be(rec + 12);
    }

    if (ctx->offset + 16 + incl_len > ctx->file_size) {
        /* Truncated packet at EOF */
        return false;
    }

    *out_sec = sec;
    *out_usec = usec;
    *out_caplen = (uint16_t)incl_len;
    *out_wirelen = (uint16_t)orig_len;
    *out_data = rec + 16;

    ctx->offset += 16 + incl_len;
    ctx->packet_count++;

    return true;
}
