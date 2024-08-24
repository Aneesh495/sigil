# Sigil::PCAP::Header - Libpcap and PCAPNG file format constants and headers
#
# Defines magic signatures, endianness indicators, link-layer encapsulation types,
# and block type identifiers for classic PCAP and modern PCAPNG capture formats.

unit package Sigil::PCAP;

use Sigil::Types;

# Classic PCAP 32-bit Magic Numbers
our constant PCAP_MAGIC_MICRO_BE is export = 0xA1B2C3D4; # Microsecond big-endian
our constant PCAP_MAGIC_MICRO_LE is export = 0xD4C3B2A1; # Microsecond little-endian
our constant PCAP_MAGIC_NANO_BE  is export = 0xA1B23C4D; # Nanosecond big-endian
our constant PCAP_MAGIC_NANO_LE  is export = 0x4D3CB2A1; # Nanosecond little-endian

# PCAPNG 32-bit Magic Numbers and Block Types
our constant PCAPNG_SECTION_HEADER_BLOCK_MAGIC is export = 0x0A0D0D0A; # SHB (\n\r\r\n)
our constant PCAPNG_BYTE_ORDER_MAGIC           is export = 0x1A2B3C4D; # Big-endian BOM

# PCAPNG Standard Block Types
our constant PCAPNG_BLOCK_SHB is export = 0x0A0D0D0A; # Section Header Block
our constant PCAPNG_BLOCK_IDB is export = 0x00000001; # Interface Description Block
our constant PCAPNG_BLOCK_SPB is export = 0x00000003; # Simple Packet Block
our constant PCAPNG_BLOCK_NRB is export = 0x00000004; # Name Resolution Block
our constant PCAPNG_BLOCK_ISB is export = 0x00000005; # Interface Statistics Block
our constant PCAPNG_BLOCK_EPB is export = 0x00000006; # Enhanced Packet Block

# Common Link-Layer Encapsulation Types (LinkType / DLT)
our constant LINKTYPE_NULL        is export = 0;
our constant LINKTYPE_ETHERNET    is export = 1;
our constant LINKTYPE_RAW         is export = 12;
our constant LINKTYPE_LINUX_SLL   is export = 113; # Linux "cooked" capture v1
our constant LINKTYPE_IEEE802_11  is export = 105; # 802.11 wireless
our constant LINKTYPE_LINUX_SLL2  is export = 276; # Linux "cooked" capture v2

# Global Header representation for classic PCAP
class GlobalHeader {
    has Int $.magic is required;
    has Int $.version-major = 2;
    has Int $.version-minor = 4;
    has Int $.thiszone = 0;
    has Int $.sigfigs = 0;
    has Int $.snaplen = 65535;
    has Int $.linktype = LINKTYPE_ETHERNET;
    has Bool $.is-little-endian = False;
    has Bool $.is-nanosecond = False;

    # Serialize global header to 24-byte wire representation
    method to-bytes(--> Buf) {
        my @b;
        my $m = $!magic;
        if $!is-little-endian {
            @b.push($m +& 0xFF);
            @b.push(($m +> 8) +& 0xFF);
            @b.push(($m +> 16) +& 0xFF);
            @b.push(($m +> 24) +& 0xFF);

            @b.push($!version-major +& 0xFF, ($!version-major +> 8) +& 0xFF);
            @b.push($!version-minor +& 0xFF, ($!version-minor +> 8) +& 0xFF);

            @b.push(0, 0, 0, 0); # thiszone
            @b.push(0, 0, 0, 0); # sigfigs

            @b.push($!snaplen +& 0xFF, ($!snaplen +> 8) +& 0xFF, ($!snaplen +> 16) +& 0xFF, ($!snaplen +> 24) +& 0xFF);
            @b.push($!linktype +& 0xFF, ($!linktype +> 8) +& 0xFF, ($!linktype +> 16) +& 0xFF, ($!linktype +> 24) +& 0xFF);
        } else {
            @b.push(($m +> 24) +& 0xFF);
            @b.push(($m +> 16) +& 0xFF);
            @b.push(($m +> 8) +& 0xFF);
            @b.push($m +& 0xFF);

            @b.push(($!version-major +> 8) +& 0xFF, $!version-major +& 0xFF);
            @b.push(($!version-minor +> 8) +& 0xFF, $!version-minor +& 0xFF);

            @b.push(0, 0, 0, 0); # thiszone
            @b.push(0, 0, 0, 0); # sigfigs

            @b.push(($!snaplen +> 24) +& 0xFF, ($!snaplen +> 16) +& 0xFF, ($!snaplen +> 8) +& 0xFF, $!snaplen +& 0xFF);
            @b.push(($!linktype +> 24) +& 0xFF, ($!linktype +> 16) +& 0xFF, ($!linktype +> 8) +& 0xFF, $!linktype +& 0xFF);
        }

        return Buf.new(@b);
    }
}
