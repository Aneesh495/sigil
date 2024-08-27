/*
 * sigil_pcap_fast.h - Memory-mapped zero-copy PCAP reader in C
 *
 * Provides line-rate packet parsing across big-endian, little-endian,
 * microsecond, and nanosecond capture files.
 */

#ifndef SIGIL_PCAP_FAST_H
#define SIGIL_PCAP_FAST_H

#include "sigil_types.h"

typedef struct sigil_pcap_ctx {
    int fd;
    size_t file_size;
    const uint8_t *mapped;
    size_t offset;
    bool is_little_endian;
    bool is_nanosecond;
    uint32_t linktype;
    uint32_t snaplen;
    uint64_t packet_count;
} sigil_pcap_ctx_t;

/* Open and mmap PCAP trace file */
int sigil_pcap_open(sigil_pcap_ctx_t *ctx, const char *filepath);

/* Close and unmap file */
void sigil_pcap_close(sigil_pcap_ctx_t *ctx);

/* Read next packet record directly referencing mmapped memory */
bool sigil_pcap_next(sigil_pcap_ctx_t *ctx, const uint8_t **out_data, uint16_t *out_caplen, uint16_t *out_wirelen, uint32_t *out_sec, uint32_t *out_usec);

#endif /* SIGIL_PCAP_FAST_H */
