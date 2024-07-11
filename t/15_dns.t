# Test suite for Sigil::Grammar::Protocol::DNS
use Test;
use Sigil::Grammar::Protocol::DNS;
use Sigil::Types;

plan 11;

# Standard DNS Query for "example.com" (Type A, Class IN):
# TxID = 0x1234, Flags = 0x0100 (Standard query, RD=1)
# QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
# QNAME = \x07example\x03com\x00, QTYPE = 1 (A), QCLASS = 1 (IN)
my $dns_query = Buf.new(
    0x12, 0x34,                         # TxID 0x1234
    0x01, 0x00,                         # Flags: Standard query, RD=1
    0x00, 0x01,                         # QDCOUNT = 1
    0x00, 0x00,                         # ANCOUNT = 0
    0x00, 0x00,                         # NSCOUNT = 0
    0x00, 0x00,                         # ARCOUNT = 0
    # QNAME: 7 "example" 3 "com" 0
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
    0x00, 0x01,                         # QTYPE = A (1)
    0x00, 0x01                          # QCLASS = IN (1)
);

my $layer_q = Sigil::Grammar::Protocol::DNS.dissect($dns_query);
is $layer_q.name, "DNS", "Layer identified as DNS";
is $layer_q.status, STATUS_OK, "Status is OK";
is $layer_q.val("dns.id"), 0x1234, "Transaction ID parsed as 0x1234";
is $layer_q.val("dns.flags.response"), False, "QR flag is False (Query)";
is $layer_q.val("dns.flags.recdesired"), True, "Recursion Desired flag is True";
is $layer_q.val("dns.count.queries"), 1, "Question count is 1";
is $layer_q.val("dns.qry.name"), "example.com", "QNAME 'example.com' parsed accurately";
is $layer_q.val("dns.qry.type"), 1, "QTYPE is 1 (A)";

# DNS Response for "example.com" with answer 93.184.216.34:
# Flags = 0x8180 (Response, RD=1, RA=1, NoError)
# ANCOUNT = 1
# Answer: NAME pointer 0xC00C, TYPE 1 (A), CLASS 1, TTL 300, RDLENGTH 4, RDATA 93.184.216.34
my $dns_resp = Buf.new(
    0x12, 0x34,
    0x81, 0x80,                         # Response, RD=1, RA=1
    0x00, 0x01,                         # QDCOUNT = 1
    0x00, 0x01,                         # ANCOUNT = 1
    0x00, 0x00,
    0x00, 0x00,
    # Question
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    # Answer RR: Name pointer 0xC00C (points to offset 12: "example.com")
    0xc0, 0x0c,
    0x00, 0x01,                         # TYPE = A (1)
    0x00, 0x01,                         # CLASS = IN (1)
    0x00, 0x00, 0x01, 0x2c,             # TTL = 300
    0x00, 0x04,                         # RDLENGTH = 4
    93, 184, 216, 34                    # 93.184.216.34
);

my $layer_r = Sigil::Grammar::Protocol::DNS.dissect($dns_resp);
is $layer_r.val("dns.flags.response"), True, "QR flag is True (Response)";
is $layer_r.val("dns.count.answers"), 1, "Answer count is 1";

# Truncated DNS header
my $trunc_raw = Buf.new(0x12, 0x34, 0x01);
my $layer_trunc = Sigil::Grammar::Protocol::DNS.dissect($trunc_raw);
is $layer_trunc.status, STATUS_TRUNCATED, "Truncated DNS header yields STATUS_TRUNCATED";
