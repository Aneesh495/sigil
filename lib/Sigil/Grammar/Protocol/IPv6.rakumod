# Sigil::Grammar::Protocol::IPv6 - Internet Protocol version 6 dissector (RFC 8200)
#
# Parses 40-byte base IPv6 headers, Traffic Class, Flow Label, 128-bit addresses,
# and traverses the chained extension header sequence (Hop-by-Hop, Routing, Fragment).

unit class Sigil::Grammar::Protocol::IPv6;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing IPv6 packet
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base IPv6 fixed header requires 40 bytes
    if $buf.remaining < 40 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("IPv6"),
            :display-name("Internet Protocol Version 6 (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("IPv6 packet truncated: expected 40 bytes for base header")
        );
    }

    my $start-offset = $buf.offset;

    # First 4 bytes: Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    my $w0 = $buf.read-uint32-be();
    my $version = $w0 +> 28;
    my $traffic-class = ($w0 +> 20) +& 0xFF;
    my $flow-label = $w0 +& 0x000FFFFF;

    my $payload-len = $buf.read-uint16-be();
    my $next-header = $buf.read-uint8();
    my $hop-limit = $buf.read-uint8();

    my $src-ip = $buf.read-ipv6();
    my $dst-ip = $buf.read-ipv6();

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::BitField.new(
        :name("Version"),
        :key("ipv6.version"),
        :offset-bytes(0),
        :length-bytes(1),
        :bit-offset(0),
        :bit-length(4),
        :value($version)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Traffic Class"),
        :key("ipv6.tclass"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($traffic-class)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Flow Label"),
        :key("ipv6.flow"),
        :offset-bytes(1),
        :length-bytes(3),
        :value($flow-label),
        :radix("hex"),
        :bit-width(20)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Payload Length"),
        :key("ipv6.plen"),
        :offset-bytes(4),
        :length-bytes(2),
        :value($payload-len)
    ));

    $fl.add(Sigil::Core::EnumField.new(
        :name("Next Header"),
        :key("ipv6.nxt"),
        :offset-bytes(6),
        :length-bytes(1),
        :value($next-header),
        :name-map(%(
            0  => "Hop-by-Hop Options",
            6  => "TCP",
            17 => "UDP",
            41 => "IPv6-in-IPv4",
            43 => "Routing",
            44 => "Fragment",
            50 => "ESP",
            51 => "AH",
            58 => "ICMPv6",
            59 => "No Next Header",
            60 => "Destination Options"
        ))
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Hop Limit"),
        :key("ipv6.hlim"),
        :offset-bytes(7),
        :length-bytes(1),
        :value($hop-limit)
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Source IPv6"),
        :key("ipv6.src"),
        :offset-bytes(8),
        :length-bytes(16),
        :value($src-ip),
        :address-type("ipv6")
    ));

    $fl.add(Sigil::Core::AddressField.new(
        :name("Destination IPv6"),
        :key("ipv6.dst"),
        :offset-bytes(24),
        :length-bytes(16),
        :value($dst-ip),
        :address-type("ipv6")
    ));

    # Traverse extension header chain
    my $curr-proto = $next-header;
    my $total-header-len = 40;
    my @ext-headers;

    while $curr-proto == (0 | 43 | 44 | 60) && $buf.remaining >= 8 {
        my $ext-type = $curr-proto;
        my $ext-nxt = $buf.read-uint8();
        my $ext-len-byte = $buf.read-uint8();
        my $ext-len = 0;

        if $ext-type == 44 { # Fragment header has fixed length of 8 bytes
            my $frag-offset-flags = $buf.read-uint16-be();
            my $frag-id = $buf.read-uint32-be();
            $ext-len = 8;
            @ext-headers.push({
                type => "Fragment",
                next => $ext-nxt,
                offset => ($frag-offset-flags +> 3) * 8,
                more => ($frag-offset-flags +& 0x01) == 1,
                id => $frag-id
            });
        } else { # Hop-by-Hop, Routing, Destination Options: length in 8-octet units minus 1
            $ext-len = ($ext-len-byte + 1) * 8;
            my $rem-ext = $ext-len - 2;
            $buf.skip(min($rem-ext, $buf.remaining));
            @ext-headers.push({
                type => ($ext-type == 0 ?? "Hop-by-Hop" !! ($ext-type == 43 ?? "Routing" !! "Destination Options")),
                next => $ext-nxt,
                length => $ext-len
            });
        }

        $total-header-len += $ext-len;
        $curr-proto = $ext-nxt;
    }

    my $raw-header = $raw.subbuf($start-offset, min($total-header-len, $raw.elems - $start-offset));
    my $avail-payload = $raw.elems - ($start-offset + $total-header-len);
    my $raw-payload = $avail-payload > 0 ?? $raw.subbuf($start-offset + $total-header-len) !! Buf.new;

    return Sigil::Core::Layer.new(
        :name("IPv6"),
        :display-name(sprintf("IPv6 (%s -> %s)", $src-ip, $dst-ip)),
        :offset($offset),
        :header-length($total-header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol($curr-proto)
    );
}
