# Test suite for Sigil::Grammar::Protocol::ARP
use Test;
use Sigil::Grammar::Protocol::ARP;
use Sigil::Types;

plan 10;

# Standard ARP Request: Who has 192.168.1.1? Tell 192.168.1.50
my $arp_req = Buf.new(
    0x00, 0x01,                         # HW type: Ethernet (1)
    0x08, 0x00,                         # Proto type: IPv4 (0x0800)
    0x06,                               # HW size: 6
    0x04,                               # Proto size: 4
    0x00, 0x01,                         # Opcode: Request (1)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # Sender MAC
    192, 168, 1, 50,                    # Sender IP
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Target MAC (unknown)
    192, 168, 1, 1                      # Target IP
);

my $layer_req = Sigil::Grammar::Protocol::ARP.dissect($arp_req);
is $layer_req.name, "ARP", "Layer identified as ARP";
is $layer_req.status, STATUS_OK, "Dissection status OK";
is $layer_req.val("arp.opcode"), 1, "Opcode is 1 (Request)";
is $layer_req.val("arp.src.hw_mac"), "00:11:22:33:44:55", "Sender MAC parsed";
is $layer_req.val("arp.src.proto_ipv4"), "192.168.1.50", "Sender IP parsed";
is $layer_req.val("arp.dst.proto_ipv4"), "192.168.1.1", "Target IP parsed";
is $layer_req.val("arp.is_gratuitous"), False, "Standard request is not gratuitous";

# Gratuitous ARP: Sender IP == Target IP (192.168.1.100 announces its presence)
my $arp_grat = Buf.new(
    0x00, 0x01,
    0x08, 0x00,
    0x06,
    0x04,
    0x00, 0x02,                         # Opcode: Reply (2)
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    192, 168, 1, 100,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # Broadcast target MAC
    192, 168, 1, 100                    # Target IP == Sender IP
);
my $layer_grat = Sigil::Grammar::Protocol::ARP.dissect($arp_grat);
is $layer_grat.val("arp.opcode"), 2, "Opcode is 2 (Reply)";
is $layer_grat.val("arp.is_gratuitous"), True, "Gratuitous ARP flag detected";

# Truncated ARP packet
my $trunc_arp = Buf.new(0x00, 0x01, 0x08, 0x00);
my $layer_trunc = Sigil::Grammar::Protocol::ARP.dissect($trunc_arp);
is $layer_trunc.status, STATUS_TRUNCATED, "Truncated ARP packet yields STATUS_TRUNCATED";
