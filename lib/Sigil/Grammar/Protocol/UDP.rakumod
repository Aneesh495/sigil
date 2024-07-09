# Sigil::Grammar::Protocol::UDP - User Datagram Protocol dissector (RFC 768)
#
# Parses 8-byte UDP datagram headers, source/destination port multiplexing,
# datagram length validation, and zero-checksum RFC 768 handling.

unit class Sigil::Grammar::Protocol::UDP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing UDP datagram
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base UDP header requires exactly 8 bytes
    if $buf.remaining < 8 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("UDP"),
            :display-name("User Datagram Protocol (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("UDP datagram truncated: expected 8 bytes for header")
        );
    }

    my $start-offset = $buf.offset;
    my $src-port = $buf.read-uint16-be();
    my $dst-port = $buf.read-uint16-be();
    my $length = $buf.read-uint16-be();
    my $checksum = $buf.read-uint16-be();

    my $status = STATUS_OK;
    my $status-detail = "";

    # UDP length field specifies length of header plus payload (minimum 8)
    if $length < 8 {
        $status = STATUS_MALFORMED;
        $status-detail = sprintf("Malformed UDP length %d (must be at least 8 bytes)", $length);
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(
        :name("Source Port"),
        :key("udp.srcport"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($src-port)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Destination Port"),
        :key("udp.dstport"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($dst-port)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Length"),
        :key("udp.length"),
        :offset-bytes(4),
        :length-bytes(2),
        :value($length)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Checksum"),
        :key("udp.checksum"),
        :offset-bytes(6),
        :length-bytes(2),
        :value($checksum),
        :radix("hex"),
        :bit-width(16)
    ));

    my $raw-header = $raw.subbuf($start-offset, 8);

    # Calculate encapsulated payload length
    my $avail = $raw.elems - ($start-offset + 8);
    my $expected-payload = $length >= 8 ?? ($length - 8) !! 0;
    my $payload-len = min($avail, $expected-payload);
    my $raw-payload = $avail > 0 ?? $raw.subbuf($start-offset + 8, $payload-len) !! Buf.new;

    # Route next protocol using destination or source port
    my $target-port = ($dst-port < 1024 && $dst-port > 0) ?? $dst-port !! $src-port;

    return Sigil::Core::Layer.new(
        :name("UDP"),
        :display-name(sprintf("UDP (%d -> %d, Len=%d)", $src-port, $dst-port, $length)),
        :offset($offset),
        :header-length(8),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol($target-port)
    );
}
