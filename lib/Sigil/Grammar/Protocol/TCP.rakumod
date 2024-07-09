# Sigil::Grammar::Protocol::TCP - Transmission Control Protocol dissector (RFC 9293)
#
# Parses 20-to-60 byte TCP segments, all 9 RFC 9293 control flags, sequence/ack numbering,
# window advertisement, and TCP options (MSS, Window Scale, SACK Permitted, SACK, Timestamps).

unit class Sigil::Grammar::Protocol::TCP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing TCP segment
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base TCP header requires at least 20 bytes
    if $buf.remaining < 20 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("TCP"),
            :display-name("Transmission Control Protocol (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("TCP segment truncated: expected at least 20 bytes for header")
        );
    }

    my $start-offset = $buf.offset;
    my $src-port = $buf.read-uint16-be();
    my $dst-port = $buf.read-uint16-be();
    my $seq-num  = $buf.read-uint32-be();
    my $ack-num  = $buf.read-uint32-be();

    my $offset-flags = $buf.read-uint16-be();
    my $data-offset = $offset-flags +> 12;
    my $header-len = $data-offset * 4;

    my $flag-ns  = ($offset-flags +> 8) +& 0x01;
    my $flag-cwr = ($offset-flags +> 7) +& 0x01;
    my $flag-ece = ($offset-flags +> 6) +& 0x01;
    my $flag-urg = ($offset-flags +> 5) +& 0x01;
    my $flag-ack = ($offset-flags +> 4) +& 0x01;
    my $flag-psh = ($offset-flags +> 3) +& 0x01;
    my $flag-rst = ($offset-flags +> 2) +& 0x01;
    my $flag-syn = ($offset-flags +> 1) +& 0x01;
    my $flag-fin = $offset-flags +& 0x01;

    my $window-size = $buf.read-uint16-be();
    my $checksum    = $buf.read-uint16-be();
    my $urgent-ptr  = $buf.read-uint16-be();

    my $status = STATUS_OK;
    my $status-detail = "";

    if $data-offset < 5 {
        $status = STATUS_MALFORMED;
        $status-detail = sprintf("Invalid TCP data offset %d (must be at least 5 for 20 bytes)", $data-offset);
    } elsif $buf.remaining < ($header-len - 20) {
        $status = STATUS_TRUNCATED;
        $status-detail = sprintf("Truncated TCP options: buffer has %d bytes, need %d", $buf.remaining, $header-len - 20);
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::IntField.new(
        :name("Source Port"),
        :key("tcp.srcport"),
        :offset-bytes(0),
        :length-bytes(2),
        :value($src-port)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Destination Port"),
        :key("tcp.dstport"),
        :offset-bytes(2),
        :length-bytes(2),
        :value($dst-port)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Sequence Number (raw)"),
        :key("tcp.seq"),
        :offset-bytes(4),
        :length-bytes(4),
        :value($seq-num)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Acknowledgment Number (raw)"),
        :key("tcp.ack"),
        :offset-bytes(8),
        :length-bytes(4),
        :value($ack-num)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Header Length"),
        :key("tcp.hdr_len"),
        :offset-bytes(12),
        :length-bytes(1),
        :value($header-len)
    ));

    # Flags bitmask and individual flags
    my $flags-val = $offset-flags +& 0x01FF;
    $fl.add(Sigil::Core::IntField.new(
        :name("Flags"),
        :key("tcp.flags"),
        :offset-bytes(12),
        :length-bytes(2),
        :value($flags-val),
        :radix("hex"),
        :bit-width(12)
    ));

    $fl.add(Sigil::Core::FlagField.new(:name("FIN"), :key("tcp.flags.fin"), :offset-bytes(13), :length-bytes(1), :mask(0x01), :is-set($flag-fin == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("SYN"), :key("tcp.flags.syn"), :offset-bytes(13), :length-bytes(1), :mask(0x02), :is-set($flag-syn == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("RST"), :key("tcp.flags.rst"), :offset-bytes(13), :length-bytes(1), :mask(0x04), :is-set($flag-rst == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("PSH"), :key("tcp.flags.psh"), :offset-bytes(13), :length-bytes(1), :mask(0x08), :is-set($flag-psh == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("ACK"), :key("tcp.flags.ack"), :offset-bytes(13), :length-bytes(1), :mask(0x10), :is-set($flag-ack == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("URG"), :key("tcp.flags.urg"), :offset-bytes(13), :length-bytes(1), :mask(0x20), :is-set($flag-urg == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("ECE"), :key("tcp.flags.ece"), :offset-bytes(13), :length-bytes(1), :mask(0x40), :is-set($flag-ece == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("CWR"), :key("tcp.flags.cwr"), :offset-bytes(13), :length-bytes(1), :mask(0x80), :is-set($flag-cwr == 1)));
    $fl.add(Sigil::Core::FlagField.new(:name("NS"),  :key("tcp.flags.ns"),  :offset-bytes(12), :length-bytes(1), :mask(0x100), :is-set($flag-ns == 1)));

    $fl.add(Sigil::Core::IntField.new(
        :name("Window Size"),
        :key("tcp.window_size"),
        :offset-bytes(14),
        :length-bytes(2),
        :value($window-size)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Checksum"),
        :key("tcp.checksum"),
        :offset-bytes(16),
        :length-bytes(2),
        :value($checksum),
        :radix("hex"),
        :bit-width(16)
    ));

    $fl.add(Sigil::Core::IntField.new(
        :name("Urgent Pointer"),
        :key("tcp.urgent_pointer"),
        :offset-bytes(18),
        :length-bytes(2),
        :value($urgent-ptr)
    ));

    # Parse TCP options
    my $options-len = $header-len - 20;
    if $options-len > 0 && $buf.remaining >= $options-len {
        my $opt-consumed = 0;
        while $opt-consumed < $options-len && $buf.remaining > 0 {
            my $kind = $buf.read-uint8();
            $opt-consumed++;

            if $kind == 0 { # EOOL
                last;
            } elsif $kind == 1 { # NOP
                next;
            } elsif $kind == 2 && $opt-consumed + 3 <= $options-len && $buf.remaining >= 3 { # MSS
                my $opt-len = $buf.read-uint8();
                my $mss-val = $buf.read-uint16-be();
                $opt-consumed += 3;
                $fl.add(Sigil::Core::IntField.new(
                    :name("Maximum Segment Size (MSS)"),
                    :key("tcp.options.mss"),
                    :offset-bytes(20 + $opt-consumed - 4),
                    :length-bytes(4),
                    :value($mss-val)
                ));
            } elsif $kind == 3 && $opt-consumed + 2 <= $options-len && $buf.remaining >= 2 { # Window Scale
                my $opt-len = $buf.read-uint8();
                my $shift = $buf.read-uint8();
                $opt-consumed += 2;
                $fl.add(Sigil::Core::IntField.new(
                    :name("Window Scale Shift Count"),
                    :key("tcp.options.wscale"),
                    :offset-bytes(20 + $opt-consumed - 3),
                    :length-bytes(3),
                    :value($shift)
                ));
            } elsif $kind == 4 && $opt-consumed + 1 <= $options-len && $buf.remaining >= 1 { # SACK Permitted
                my $opt-len = $buf.read-uint8();
                $opt-consumed += 1;
                $fl.add(Sigil::Core::FlagField.new(
                    :name("SACK Permitted"),
                    :key("tcp.options.sack_perm"),
                    :offset-bytes(20 + $opt-consumed - 2),
                    :length-bytes(2),
                    :mask(0),
                    :is-set(True)
                ));
            } elsif $kind == 8 && $opt-consumed + 9 <= $options-len && $buf.remaining >= 9 { # Timestamps
                my $opt-len = $buf.read-uint8();
                my $tsval = $buf.read-uint32-be();
                my $tsecr = $buf.read-uint32-be();
                $opt-consumed += 9;
                $fl.add(Sigil::Core::IntField.new(
                    :name("Timestamp Value (TSval)"),
                    :key("tcp.options.timestamp.tsval"),
                    :offset-bytes(20 + $opt-consumed - 10),
                    :length-bytes(4),
                    :value($tsval)
                ));
                $fl.add(Sigil::Core::IntField.new(
                    :name("Timestamp Echo Reply (TSecr)"),
                    :key("tcp.options.timestamp.tsecr"),
                    :offset-bytes(20 + $opt-consumed - 6),
                    :length-bytes(4),
                    :value($tsecr)
                ));
            } else {
                # Generic option fallback
                if $buf.remaining >= 1 {
                    my $opt-len = $buf.read-uint8();
                    $opt-consumed++;
                    my $rem-opt = $opt-len - 2;
                    if $rem-opt > 0 && $buf.remaining >= $rem-opt {
                        $buf.skip($rem-opt);
                        $opt-consumed += $rem-opt;
                    }
                }
            }
        }
    }

    my $raw-header = $raw.subbuf($start-offset, min($header-len, $raw.elems - $start-offset));
    my $avail = $raw.elems - ($start-offset + $header-len);
    my $raw-payload = $avail > 0 ?? $raw.subbuf($start-offset + $header-len) !! Buf.new;

    # Format flag string summary (e.g. "[SYN, ACK]")
    my $flag-summary = Sigil::Types::tcp-flags-to-str($flags-val);

    # Application layer port routing
    my $app-port = ($dst-port < 1024 && $dst-port > 0) ?? $dst-port !! $src-port;

    return Sigil::Core::Layer.new(
        :name("TCP"),
        :display-name(sprintf("TCP (%d -> %d [%s] Seq=%u Ack=%u Win=%d)", $src-port, $dst-port, $flag-summary, $seq-num, $ack-num, $window-size)),
        :offset($offset),
        :header-length($header-len),
        :payload-length($raw-payload.elems),
        :raw-header($raw-header),
        :raw-payload($raw-payload),
        :fields($fl),
        :status($status),
        :status-detail($status-detail),
        :next-protocol($app-port)
    );
}
