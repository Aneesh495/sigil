# Sigil::Grammar::Protocol::WebSocket - WebSocket Framing protocol dissector (RFC 6455)
#
# Parses RFC 6455 data frames, control frames (Ping, Pong, Close), variable length
# payload descriptors (7-bit, 16-bit, 64-bit), and performs 4-byte masking-key XOR unmasking.

unit class Sigil::Grammar::Protocol::WebSocket;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing WebSocket frame
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base WebSocket frame requires at least 2 bytes
    if $buf.remaining < 2 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("WebSocket"),
            :display-name("WebSocket (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("WebSocket frame truncated: expected at least 2 bytes for base frame")
        );
    }

    my $start-offset = $buf.offset;

    # Byte 0: FIN (1 bit), RSV1-3 (3 bits), Opcode (4 bits)
    my $b0 = $buf.read-uint8();
    my $fin    = ($b0 +> 7) +& 0x01;
    my $rsv1   = ($b0 +> 6) +& 0x01;
    my $rsv2   = ($b0 +> 5) +& 0x01;
    my $rsv3   = ($b0 +> 4) +& 0x01;
    my $opcode = $b0 +& 0x0F;

    # Byte 1: Mask (1 bit), Payload len code (7 bits)
    my $b1 = $buf.read-uint8();
    my $is-masked = ($b1 +> 7) +& 0x01;
    my $len-code  = $b1 +& 0x7F;

    my %opcodes = (
        0  => "Continuation Frame",
        1  => "Text Frame",
        2  => "Binary Frame",
        8  => "Connection Close",
        9  => "Ping",
        10 => "Pong"
    );

    # Determine extended payload length
    my $payload-len = $len-code;
    my $ext-len-bytes = 0;

    if $len-code == 126 {
        if $buf.remaining < 2 {
            # Truncated extended length
            return Sigil::Core::Layer.new(
                :name("WebSocket"),
                :display-name("WebSocket (Truncated Length)"),
                :offset($offset),
                :header-length($buf.remaining),
                :payload-length(0),
                :raw-header($buf.read-remaining),
                :raw-payload(Buf.new),
                :fields(Sigil::Core::FieldList.new),
                :status(STATUS_TRUNCATED),
                :status-detail("Truncated 16-bit extended payload length")
            );
        }
        $payload-len = $buf.read-uint16-be();
        $ext-len-bytes = 2;
    } elsif $len-code == 127 {
        if $buf.remaining < 8 {
            return Sigil::Core::Layer.new(
                :name("WebSocket"),
                :display-name("WebSocket (Truncated Length)"),
                :offset($offset),
                :header-length($buf.remaining),
                :payload-length(0),
                :raw-header($buf.read-remaining),
                :raw-payload(Buf.new),
                :fields(Sigil::Core::FieldList.new),
                :status(STATUS_TRUNCATED),
                :status-detail("Truncated 64-bit extended payload length")
            );
        }
        $payload-len = $buf.read-uint64-be();
        $ext-len-bytes = 8;
    }

    # Extract 4-byte masking key if present
    my Buf $mask-key = Buf.new;
    if $is-masked == 1 {
        if $buf.remaining < 4 {
            return Sigil::Core::Layer.new(
                :name("WebSocket"),
                :display-name("WebSocket (Truncated Mask)"),
                :offset($offset),
                :header-length($buf.remaining),
                :payload-length(0),
                :raw-header($buf.read-remaining),
                :raw-payload(Buf.new),
                :fields(Sigil::Core::FieldList.new),
                :status(STATUS_TRUNCATED),
                :status-detail("Truncated 4-byte masking key")
            );
        }
        $mask-key = $buf.read-bytes(4);
    }

    my $header-len = 2 + $ext-len-bytes + ($is-masked == 1 ?? 4 !! 0);
    my $raw-header = $raw.subbuf($start-offset, $header-len);

    # Read and unmask payload
    my $avail-payload = min($buf.remaining, $payload-len);
    my $masked-slice = $avail-payload > 0 ?? $buf.read-bytes($avail-payload) !! Buf.new;
    my $unmasked-slice = Buf.new;

    if $is-masked == 1 && $masked-slice.elems > 0 {
        my @unmasked;
        for 0 ..^ $masked-slice.elems -> $i {
            my $b = $masked-slice[$i] +^ $mask-key[$i % 4];
            @unmasked.push($b);
        }
        $unmasked-slice = Buf.new(@unmasked);
    } else {
        $unmasked-slice = $masked-slice;
    }

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::FlagField.new(:name("Fin"), :key("ws.fin"), :offset-bytes(0), :length-bytes(1), :mask(0x80), :is-set($fin == 1)));
    $fl.add(Sigil::Core::EnumField.new(:name("Opcode"), :key("ws.opcode"), :offset-bytes(0), :length-bytes(1), :value($opcode), :name-map(%opcodes)));
    $fl.add(Sigil::Core::FlagField.new(:name("Masked"), :key("ws.mask"), :offset-bytes(1), :length-bytes(1), :mask(0x80), :is-set($is-masked == 1)));
    $fl.add(Sigil::Core::IntField.new(:name("Payload Length"), :key("ws.length"), :offset-bytes(1), :length-bytes(1 + $ext-len-bytes), :value($payload-len)));

    if $is-masked == 1 {
        $fl.add(Sigil::Core::BytesField.new(:name("Masking Key"), :key("ws.mask_key"), :offset-bytes(2 + $ext-len-bytes), :length-bytes(4), :raw($mask-key)));
    }

    # If text frame (opcode 1), decode unmasked payload string
    my $unmasked-text = "";
    if $opcode == 1 && $unmasked-slice.elems > 0 {
        try {
            $unmasked-text = $unmasked-slice.decode('utf-8');
            $fl.add(Sigil::Core::StringField.new(:name("Text Payload"), :key("ws.payload_text"), :value($unmasked-text)));
        }
    }

    my $op-desc = %opcodes{$opcode} // sprintf("Opcode %d", $opcode);
    my $disp = $unmasked-text ne ""
        ?? sprintf("WebSocket %s (Len=%d) \"%s\"", $op-desc, $payload-len, $unmasked-text.substr(0, 32))
        !! sprintf("WebSocket %s (Len=%d, Masked=%d)", $op-desc, $payload-len, $is-masked);

    return Sigil::Core::Layer.new(
        :name("WebSocket"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length($unmasked-slice.elems),
        :raw-header($raw-header),
        :raw-payload($unmasked-slice),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
