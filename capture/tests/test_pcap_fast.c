/*
 * test_pcap_fast.c - Unit tests for memory-mapped C PCAP reader
 */

#include "sigil_pcap_fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

static void create_test_pcap(const char *path) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);

    /* 24-byte PCAP header (little-endian microsecond: D4 C3 B2 A1) */
    const uint8_t magic_le[4] = {0xD4, 0xC3, 0xB2, 0xA1};
    uint16_t v_maj = 2, v_min = 4;
    int32_t tz = 0;
    uint32_t sigfigs = 0, snaplen = 65535, linktype = 1;

    fwrite(magic_le, 4, 1, f);
    fwrite(&v_maj, 2, 1, f);
    fwrite(&v_min, 2, 1, f);
    fwrite(&tz, 4, 1, f);
    fwrite(&sigfigs, 4, 1, f);
    fwrite(&snaplen, 4, 1, f);
    fwrite(&linktype, 4, 1, f);

    /* Packet 1 */
    uint32_t sec = 1700000000, usec = 100000;
    uint32_t caplen = 10, origlen = 10;
    const char payload1[] = "PACKET_001";

    fwrite(&sec, 4, 1, f);
    fwrite(&usec, 4, 1, f);
    fwrite(&caplen, 4, 1, f);
    fwrite(&origlen, 4, 1, f);
    fwrite(payload1, 10, 1, f);

    /* Packet 2 */
    sec = 1700000001; usec = 200000;
    caplen = 12; origlen = 12;
    const char payload2[] = "PACKET_00002";

    fwrite(&sec, 4, 1, f);
    fwrite(&usec, 4, 1, f);
    fwrite(&caplen, 4, 1, f);
    fwrite(&origlen, 4, 1, f);
    fwrite(payload2, 12, 1, f);

    fclose(f);
}

int main(void) {
    printf("Running Sigil Fast PCAP Reader Tests...\n");
    const char *path = "/tmp/sigil_test_fast.pcap";
    create_test_pcap(path);

    sigil_pcap_ctx_t ctx;
    assert(sigil_pcap_open(&ctx, path) == 0);
    assert(ctx.is_little_endian == true);
    assert(ctx.is_nanosecond == false);
    assert(ctx.linktype == 1);
    assert(ctx.snaplen == 65535);

    const uint8_t *data;
    uint16_t clen, wlen;
    uint32_t s, us;

    /* Packet 1 */
    assert(sigil_pcap_next(&ctx, &data, &clen, &wlen, &s, &us));
    assert(clen == 10);
    assert(wlen == 10);
    assert(s == 1700000000);
    assert(us == 100000);
    assert(memcmp(data, "PACKET_001", 10) == 0);

    /* Packet 2 */
    assert(sigil_pcap_next(&ctx, &data, &clen, &wlen, &s, &us));
    assert(clen == 12);
    assert(wlen == 12);
    assert(s == 1700000001);
    assert(us == 200000);
    assert(memcmp(data, "PACKET_00002", 12) == 0);

    /* EOF */
    assert(!sigil_pcap_next(&ctx, &data, &clen, &wlen, &s, &us));
    assert(ctx.packet_count == 2);

    sigil_pcap_close(&ctx);
    unlink(path);

    printf("  [PASS] Fast mmap PCAP reader verified.\n");
    return 0;
}
