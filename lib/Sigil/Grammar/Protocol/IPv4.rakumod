# Sigil::Grammar::Protocol::IPv4 - Internet Protocol version 4 dissector (RFC 791)
#
# Parses standard IPv4 headers, DSCP/ECN traffic classification, fragmentation
# flags, RFC 1071 header checksum validation, and variable-length IPv4 options.

unit class Sigil::Grammar::Protocol::IPv4;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Checksum;
use Sigil::Core::Error;

# Dissect raw byte buffer containing IPv4 packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Standard minimum IPv4 header requires 20 bytes
    if $buf.remaining < 20 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("IPv4"),
            :display-name("Internet Protocol Version 4 (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("IPv4 packet truncated: expected at least 20 bytes for base header")
        );
    }

    my $start-offset = $buf.offset;

    # Octet 0: Version (4 bits) and Internet Header Length (IHL 4 bits)
    my $v-ihl = $buf.read-uint8();
    my $version = $v-ihl +> 4;
    my $ihl = $v-ihl +& 0x0F;
    my $header-len = $ihl * 4;

    # Octet 1: DSCP (6 bits) and ECN (2 bits)
    my $tos = $buf.read-uint8();
    my $dscp = $tos +> 2;
    my $ecn = $tos +& 0x03;

    # Octets 2-3: Total Length
    my $total-len = $buf.read-uint16-be();

    # Octets 4-5: Identification
    my $id = $buf.read-uint16-be();

    # Octets 6-7: Flags (3 bits) and Fragment Offset (13 bits)
    my $flags-frag = $buf.read-uint16-be();
    my $flag-res = ($flags-frag +> 15) +& 0x01;
    my $flag-df  = ($flags-frag +> 14) +& 0x01;
    my $flag-mf  = ($flags-frag +> 13) +& 0x01;
    my $frag-offset = ($flags-frag +& 0x1FFF) * 8; # Converted to byte offset

    # Octet 8: TTL, Octet 9: Protocol
    my $ttl = $buf.read-uint8();
    my $proto = $buf.read-uint8();

    # Octets 10-11: Header Checksum
    my $checksum = $buf.read-uint16-be();

    # Octets 12-19: Addresses
    my $src-ip = $buf.read-ipv4();
    my $dst-ip = $buf.read-ipv4();

    # Sanity checks on version and header length
    my $status = STATUS_OK;
    my $status-detail = "";

    if $version != 4 {
        $status = STATUS_MALFORMED;
        $status-detail = sprintf("Invalid IP version %d (expected 4)", $version);
    } elsif $ihl < 5 {
        $status = STATUS_MALFORMED;
        $status-detail = sprintf("Invalid IHL %d: header cannot be smaller than 20 bytes", $ihl);
    } elsif $buf.remaining < ($header-len - 20) {
        $status = STATUS_TRUNCATED;
        $status-detail = sprintf("Truncated IPv4 options: buffer has %d bytes, need %d", $buf.remaining, $header-len - 20);
    }

    # Verify header checksum over the header slice if header is sufficiently intact
    my $checksum-valid = True;
    if $status == STATUS_OK && $raw.elems >= ($start-offset + $header-len) {
        my $hdr-slice = $raw.subbuf($start-offset, $header-len);
        $checksum-valid = Sigil::Core::Checksum::verify-internet-checksum($hdr-slice);
        if !$checksum-valid {
            $status = STATUS_CHECKSUM_MISMATCH;
            my $recalculated = Sigil::Core::Checksum::internet-checksum(
                Buf.new($hdr-slice.list.map({ $_ }))
            );
            $status-detail = sprintf("Header checksum 0x%04x invalid", $checksum);
        }
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::BitField.new(
        :name("Version"),
        :key("ip.version"),
        :offset-bytes(0),
        :length-bytes(1),
        :bit-offset(0),
        :bit-length(4),
        :value($version)
    ));

    $fl.add(Sigil::Core::BitField.new(
        :name("Header Length (IHL)"),
        :key("ip.hdr_len"),
        :offset-bytes(0),
        :length-bytes(1),
        :bit-offset(4),
        :bit-length(4),
        :value($header-len)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Differentiated Services (DSCP)"),
        :key("ip.dsfield.dscp"),
        :offset-bytes(1),
        :length-bytes(1),
        :value($dscp)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Explicit Congestion (ECN)"),
        :key("ip.dsfield.ecn"),
        :offset-bytes(1),
        :length-bytes(1),
        :value($ecn)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Total Length"),
        :key("ip.len"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($total-len)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Identification"),
        :key("ip.id"),
        :offset-bytes(4),
        :length-bytes(2),
        :value($id),
        :radix("hex"),
        :bit-width(16)
    ));

    $fl.add(Sigil::Core::FlagField.new(
        :name("Don't Fragment (DF)"),
        :key("ip.flags.df"),
        :offset-bytes(6),
        :length-bytes(2),
        :mask(0x4000),
        :is-set($flag-df == 1)
    ));

    $fl.add(Sigil::Core::FlagField.new(
        :name("More Fragments (MF)"),
        :key("ip.flags.mf"),
        :offset-bytes(6),
        :length-bytes(2),
        :mask(0x2000),
        :is-set($flag-mf == 1)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Fragment Offset"),
        :key("ip.frag_offset"),
        :offset-bytes(6),
        :length-bytes(2),
        :value($frag-offset)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Time to Live (TTL)"),
        :key("ip.ttl"),
        :offset-bytes(8),
        :length-bytes(1),
        :value($ttl)
    ));

    $fl.add(Sigil::Core::EnumField.new(
        :name("Protocol"),
        :key("ip.proto"),
        :offset-bytes(9),
        :length-bytes(1),
        :value($proto),
        :name-map(%(
            1  => "ICMP",
            2  => "IGMP",
            6  => "TCP",
            17 => "UDP",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            89 => "OSPF"
        ))
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Header Checksum"),
        :key("ip.checksum"),
        :offset-bytes(10),
        :length-bytes(2),
        :value($checksum),
        :radix("hex"),
        :bit-width(16)
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Source IP"),
        :key("ip.src"),
        :offset-bytes(12),
        :length-bytes(4),
        :value($src-ip),
        :address-type("ipv4")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Destination IP"),
        :key("ip.dst"),
        :offset-bytes(16),
        :length-bytes(4),
        :value($dst-ip),
        :address-type("ipv4")
    ));

    # Parse IPv4 Options if header length exceeds standard 20 bytes
    if $ihl > 5 && $buf.remaining >= ($header-len - 20) {
        my $opt-bytes = $buf.read-bytes($header-len - 20);
        $fl.add(Sigil::Core::BytesField.new(
            :name("IP Options"),
            :key("ip.options"),
            :offset-bytes(20),
            :length-bytes($header-len - 20),
            :raw($opt-bytes)
        ));
    }

    my $raw-header = $raw.subbuf($start-offset, min($header-len, $raw.elems - $start-offset));

    # Calculate actual payload length based on Total Length vs available wire bytes
    my $avail-payload = $raw.elems - ($start-offset + $header-len);
    my $expected-payload = $total-len >= $header-len ?? ($total-len - $header-len) !! 0;
    my $payload-len = min($avail-payload, $expected-payload);
    my $raw-payload = $avail-payload > 0 ?? $raw.subbuf($start-offset + $header-len, $payload-len) !! Buf.new;

    return Sigil::Core::Layer.new(
        :name("IPv4"),
        :display-name(sprintf("IPv4 (%s -> %s)", $src-ip, $dst-ip)),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol($proto)
    );
}
