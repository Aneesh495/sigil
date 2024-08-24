# Sigil::PCAP::PCAPNG - Next-Generation PCAP format parser (IETF Draft)
#
# Parses Section Header Blocks (SHB), Interface Description Blocks (IDB),
# and Enhanced Packet Blocks (EPB) with 32-bit boundary alignment.

unit class Sigil::PCAP::PCAPNG;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Packet;
use Sigil::Core::Error;
use Sigil::PCAP::Header;

has Buf $.raw-buffer;
has Sigil::Core::Buffer $!cursor;

has Bool $.is-little-endian = True;
has @!interfaces;                           # Array of Hash: { id, linktype, snaplen, tsresol, name }
has Int $.packet-count = 0;

submethod TWEAK() {
    if $!raw-buffer.defined && $!raw-buffer.elems >= 12 {
        $!cursor = Sigil::Core::Buffer.new($!raw-buffer);
    }
}

method from-buffer(Buf $bytes --> Sigil::PCAP::PCAPNG) {
    my $p = self.new(:raw-buffer($bytes));
    return $p;
}

method open-file(Str $path --> Sigil::PCAP::PCAPNG) {
    die Sigil::Core::FileNotFoundException.new(:filepath($path)) unless $path.IO.e;
    my $bytes = $path.IO.slurp(:bin);
    return self.from-buffer($bytes);
}

# Read next Enhanced Packet Block (EPB); returns Nil on EOF
method read-next-packet(--> Sigil::Core::Packet) {
    return Nil unless $!cursor.defined;

    while !$!cursor.is-eof {
        if $!cursor.remaining < 8 {
            return Nil;
        }

        my $block-start = $!cursor.offset;

        # Read block type as LE first to inspect
        my $b0 = $!cursor.peek-u8(0);
        my $b1 = $!cursor.peek-u8(1);
        my $b2 = $!cursor.peek-u8(2);
        my $b3 = $!cursor.peek-u8(3);
        my $type-le = ($b3 +< 24) +| ($b2 +< 16) +| ($b1 +< 8) +| $b0;
        my $type-be = ($b0 +< 24) +| ($b1 +< 16) +| ($b2 +< 8) +| $b3;

        # If Section Header Block, determine endianness from Byte-Order Magic
        if $type-be == PCAPNG_SECTION_HEADER_BLOCK_MAGIC || $type-le == PCAPNG_SECTION_HEADER_BLOCK_MAGIC {
            self.parse-shb();
            next;
        }

        # For all other blocks, read using current endianness
        my $block-type = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
        my $block-len = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();

        if $block-len < 12 || $block-len > 16777216 {
            # Invalid block length or out of bounds
            return Nil;
        }

        if $block-type == PCAPNG_BLOCK_IDB {
            self.parse-idb($block-len - 12); # 12 = type(4) + total_len(4) + trailing_len(4)
            # Skip trailing block length
            $!cursor.skip(4);
        } elsif $block-type == PCAPNG_BLOCK_EPB {
            my $pkt = self.parse-epb($block-len - 12);
            # Skip trailing block length
            $!cursor.skip(4);
            return $pkt if $pkt.defined;
        } else {
            # Skip unhandled block (SPB, NRB, ISB, Custom)
            my $payload-len = $block-len - 12;
            $!cursor.skip($payload-len) if $payload-len > 0;
            $!cursor.skip(4); # trailing block length
        }
    }

    return Nil;
}

# Parse Section Header Block
method parse-shb() {
    $!cursor.skip(4); # Block Type
    my $len-candidate = $!cursor.peek-u8(0) +| ($!cursor.peek-u8(3) +< 24);

    # Peek byte order magic at offset 8
    my $bom0 = $!cursor.peek-u8(4);
    my $bom1 = $!cursor.peek-u8(5);
    my $bom2 = $!cursor.peek-u8(6);
    my $bom3 = $!cursor.peek-u8(7);
    my $bom-be = ($bom0 +< 24) +| ($bom1 +< 16) +| ($bom2 +< 8) +| $bom3;

    if $bom-be == PCAPNG_BYTE_ORDER_MAGIC {
        $!is-little-endian = False;
    } else {
        $!is-little-endian = True;
    }

    my $block-len = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $bom = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $major = $!is-little-endian ?? $!cursor.read-u16-le() !! $!cursor.read-u16();
    my $minor = $!is-little-endian ?? $!cursor.read-u16-le() !! $!cursor.read-u16();
    my $sec-len = $!is-little-endian ?? $!cursor.read-u64-le() !! $!cursor.read-u64();

    # Skip options to end of block
    my $remaining-body = $block-len - 28;
    $!cursor.skip($remaining-body) if $remaining-body > 0;
    $!cursor.skip(4); # Trailing block length
}

# Parse Interface Description Block
method parse-idb(Int $body-len) {
    my $linktype = $!is-little-endian ?? $!cursor.read-u16-le() !! $!cursor.read-u16();
    $!cursor.skip(2); # Reserved
    my $snaplen = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();

    my %iface = (
        id       => @!interfaces.elems,
        linktype => $linktype,
        snaplen  => $snaplen,
        name     => "iface" ~ @!interfaces.elems
    );

    # Skip options if present
    my $opts-len = $body-len - 8;
    $!cursor.skip($opts-len) if $opts-len > 0;

    @!interfaces.push(%iface);
}

# Parse Enhanced Packet Block
method parse-epb(Int $body-len --> Sigil::Core::Packet) {
    my $if-id = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $ts-high = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $ts-low = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $cap-len = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();
    my $orig-len = $!is-little-endian ?? $!cursor.read-u32-le() !! $!cursor.read-u32();

    # 64-bit timestamp (default resolution 1 microsecond = 10^-6)
    my $ts-raw = ($ts-high +< 32) +| $ts-low;
    my $ts = $ts-raw.Num / 1000000e0;

    my $packet-data = $!cursor.read-bytes($cap-len);

    # Packet data is padded to 32-bit (4-byte) boundary
    my $padding = (4 - ($cap-len % 4)) % 4;
    $!cursor.skip($padding) if $padding > 0;

    # Skip any options remaining in EPB body
    my $consumed = 20 + $cap-len + $padding;
    my $opts-len = $body-len - $consumed;
    $!cursor.skip($opts-len) if $opts-len > 0;

    $!packet-count++;
    my $if-name = (@!interfaces.elems > $if-id) ?? @!interfaces[$if-id]<name> !! "if$if-id";

    return Sigil::Core::Packet.new(
        :raw($packet-data),
        :packet-id($!packet-count),
        :timestamp($ts),
        :wire-length($orig-len),
        :capture-length($cap-len),
        :interface($if-name)
    );
}

# Read all packets from PCAPNG file
method read-all(--> List) {
    my @packets;
    while self.read-next-packet() -> $pkt {
        @packets.push($pkt);
    }
    return @packets.list;
}
