# Sigil::Grammar::Protocol::SCTP - Stream Control Transmission Protocol dissector (RFC 4960)
#
# Decodes SCTP 12-byte common header and variable-length chunk chains (DATA, INIT,
# SACK, HEARTBEAT, ABORT, SHUTDOWN) with 4-byte padding alignment.

unit class Sigil::Grammar::Protocol::SCTP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

method protocol-name(--> Str) { return "SCTP"; }

our constant SCTP_CHUNK_DATA          = 0;
our constant SCTP_CHUNK_INIT          = 1;
our constant SCTP_CHUNK_INIT_ACK      = 2;
our constant SCTP_CHUNK_SACK          = 3;
our constant SCTP_CHUNK_HEARTBEAT     = 4;
our constant SCTP_CHUNK_HEARTBEAT_ACK = 5;
our constant SCTP_CHUNK_ABORT         = 6;
our constant SCTP_CHUNK_SHUTDOWN      = 7;
our constant SCTP_CHUNK_ERROR         = 9;
our constant SCTP_CHUNK_COOKIE_ECHO   = 10;
our constant SCTP_CHUNK_COOKIE_ACK    = 11;

# Dissect SCTP datagram
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 12 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("SCTP"),
            :display-name("SCTP (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED)
        );
    }

    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start = $offset;

    my $sport = $buf.read-uint16-be();
    my $dport = $buf.read-uint16-be();
    my $vtag  = $buf.read-uint32-be();
    my $csum  = $buf.read-uint32-be();

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(:name("Source Port"), :key("sctp.srcport"), :value($sport)));
    $fl.add(Sigil::Core::IntField.new(:name("Destination Port"), :key("sctp.dstport"), :value($dport)));
    $fl.add(Sigil::Core::IntField.new(:name("Verification Tag"), :key("sctp.vtag"), :value($vtag), :radix("hex"), :bit-width(32)));
    $fl.add(Sigil::Core::IntField.new(:name("Checksum"), :key("sctp.checksum"), :value($csum), :radix("hex"), :bit-width(32)));

    my @chunk-types;
    my $chunk-count = 0;

    # Parse Chunks
    while $buf.remaining >= 4 {
        my $type  = $buf.read-uint8();
        my $flags = $buf.read-uint8();
        my $len   = $buf.read-uint16-be();

        if $len < 4 {
            # Invalid chunk length
            last;
        }

        $chunk-count++;
        my $val-len = $len - 4;
        if $buf.remaining < $val-len {
            last;
        }

        my $chunk-data = $buf.read-bytes($val-len);

        # Chunks are padded to 4-byte boundary
        my $pad = (4 - ($len % 4)) % 4;
        $buf.skip($pad) if $pad > 0 && $buf.remaining >= $pad;

        given $type {
            when SCTP_CHUNK_DATA {
                @chunk-types.push("DATA");
                if $val-len >= 12 {
                    my $cbuf = Sigil::Core::Buffer.new($chunk-data);
                    my $tsn = $cbuf.read-uint32-be();
                    my $sid = $cbuf.read-uint16-be();
                    my $ssn = $cbuf.read-uint16-be();
                    my $ppid = $cbuf.read-uint32-be();

                    $fl.add(Sigil::Core::IntField.new(:name("TSN"), :key("sctp.data.tsn"), :value($tsn)));
                    $fl.add(Sigil::Core::IntField.new(:name("Stream ID"), :key("sctp.data.sid"), :value($sid)));
                    $fl.add(Sigil::Core::IntField.new(:name("Stream Seq"), :key("sctp.data.ssn"), :value($ssn)));
                    $fl.add(Sigil::Core::IntField.new(:name("PPID"), :key("sctp.data.ppid"), :value($ppid)));
                }
            }
            when SCTP_CHUNK_INIT          { @chunk-types.push("INIT"); }
            when SCTP_CHUNK_INIT_ACK      { @chunk-types.push("INIT_ACK"); }
            when SCTP_CHUNK_SACK          { @chunk-types.push("SACK"); }
            when SCTP_CHUNK_HEARTBEAT     { @chunk-types.push("HEARTBEAT"); }
            when SCTP_CHUNK_HEARTBEAT_ACK { @chunk-types.push("HEARTBEAT_ACK"); }
            when SCTP_CHUNK_ABORT         { @chunk-types.push("ABORT"); }
            when SCTP_CHUNK_SHUTDOWN      { @chunk-types.push("SHUTDOWN"); }
            default                       { @chunk-types.push("CHUNK_" ~ $type); }
        }
    }

    $fl.add(Sigil::Core::IntField.new(:name("Chunk Count"), :key("sctp.chunk_count"), :value($chunk-count)));

    my $header-len = $buf.offset - $start;
    my $chunks-str = @chunk-types.join(", ");
    my $disp = sprintf("SCTP: %d -> %d (%s)", $sport, $dport, $chunks-str ne "" ?? $chunks-str !! "No Chunks");

    return Sigil::Core::Layer.new(
        :name("SCTP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw.subbuf($start, $header-len)),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
