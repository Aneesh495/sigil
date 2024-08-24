# Sigil::PCAP::Reader - Pure-Raku streaming libpcap file parser
#
# Reads classic PCAP capture files across big-endian, little-endian, microsecond,
# and nanosecond timestamps, yielding Sigil::Core::Packet structures.

unit class Sigil::PCAP::Reader;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Packet;
use Sigil::Core::Error;
use Sigil::PCAP::Header;

has Str $.filepath;
has Buf $.raw-buffer;
has Sigil::Core::Buffer $!cursor;

has Sigil::PCAP::GlobalHeader $.header;
has Int $.packet-count = 0;
has Bool $.is-little-endian = False;
has Bool $.is-nanosecond = False;

# Open from filesystem path
method open-file(Str $path --> Sigil::PCAP::Reader) {
    die Sigil::Core::FileNotFoundException.new(:filepath($path)) unless $path.IO.e;
    my $bytes = $path.IO.slurp(:bin);
    return self.from-buffer($bytes, :filepath($path));
}

# Initialize from memory buffer
method from-buffer(Buf $bytes, Str :$filepath = "memory" --> Sigil::PCAP::Reader) {
    my $reader = self.new(:raw-buffer($bytes), :$filepath);
    $reader.init-cursor();
    return $reader;
}

submethod TWEAK() {
    if $!raw-buffer.defined && $!raw-buffer.elems >= 24 {
        self.init-cursor();
    }
}

method init-cursor() {
    $!cursor = Sigil::Core::Buffer.new($!raw-buffer);
    self.read-global-header();
}

# Parse 24-byte global PCAP header
method read-global-header() {
    if $!cursor.remaining < 24 {
        die Sigil::Core::BufferUnderflowException.new(
            :requested-bytes(24),
            :available-bytes($!cursor.remaining),
            :offset($!cursor.offset)
        );
    }

    # Inspect first 4 bytes to determine magic and endianness
    my $m0 = $!cursor.peek-u8(0);
    my $m1 = $!cursor.peek-u8(1);
    my $m2 = $!cursor.peek-u8(2);
    my $m3 = $!cursor.peek-u8(3);

    my $raw-magic-be = ($m0 +< 24) +| ($m1 +< 16) +| ($m2 +< 8) +| $m3;
    my $raw-magic-le = ($m3 +< 24) +| ($m2 +< 16) +| ($m1 +< 8) +| $m0;

    my $magic;
    if $raw-magic-be == PCAP_MAGIC_MICRO_BE {
        $!is-little-endian = False;
        $!is-nanosecond = False;
        $magic = PCAP_MAGIC_MICRO_BE;
    } elsif $raw-magic-be == PCAP_MAGIC_MICRO_LE {
        $!is-little-endian = True;
        $!is-nanosecond = False;
        $magic = PCAP_MAGIC_MICRO_BE;
    } elsif $raw-magic-be == PCAP_MAGIC_NANO_BE {
        $!is-little-endian = False;
        $!is-nanosecond = True;
        $magic = PCAP_MAGIC_NANO_BE;
    } elsif $raw-magic-be == PCAP_MAGIC_NANO_LE {
        $!is-little-endian = True;
        $!is-nanosecond = True;
        $magic = PCAP_MAGIC_NANO_BE;
    } else {
        die Sigil::Core::InvalidChecksumException.new(
            :field-name("pcap_magic"),
            :expected(PCAP_MAGIC_MICRO_BE),
            :computed($raw-magic-be)
        );
    }

    $!cursor.skip(4);

    my ($v_major, $v_minor, $thiszone, $sigfigs, $snaplen, $linktype);

    if $!is-little-endian {
        $v_major = $!cursor.read-u16-le();
        $v_minor = $!cursor.read-u16-le();
        $thiszone = $!cursor.read-u32-le();
        $sigfigs = $!cursor.read-u32-le();
        $snaplen = $!cursor.read-u32-le();
        $linktype = $!cursor.read-u32-le();
    } else {
        $v_major = $!cursor.read-u16();
        $v_minor = $!cursor.read-u16();
        $thiszone = $!cursor.read-u32();
        $sigfigs = $!cursor.read-u32();
        $snaplen = $!cursor.read-u32();
        $linktype = $!cursor.read-u32();
    }

    $!header = Sigil::PCAP::GlobalHeader.new(
        :$magic,
        :version-major($v_major),
        :version-minor($v_minor),
        :$thiszone,
        :$sigfigs,
        :$snaplen,
        :$linktype,
        :$!is-little-endian,
        :$!is-nanosecond
    );
}

# Read next packet record from stream; returns Nil on EOF
method read-next(--> Sigil::Core::Packet) {
    return Nil if $!cursor.is-eof;

    if $!cursor.remaining < 16 {
        # Trailing incomplete packet header
        return Nil;
    }

    my ($ts_sec, $ts_subsec, $incl_len, $orig_len);
    if $!is-little-endian {
        $ts_sec = $!cursor.read-u32-le();
        $ts_subsec = $!cursor.read-u32-le();
        $incl_len = $!cursor.read-u32-le();
        $orig_len = $!cursor.read-u32-le();
    } else {
        $ts_sec = $!cursor.read-u32();
        $ts_subsec = $!cursor.read-u32();
        $incl_len = $!cursor.read-u32();
        $orig_len = $!cursor.read-u32();
    }

    if $!cursor.remaining < $incl_len {
        # Truncated packet payload on EOF
        return Nil;
    }

    my $packet-bytes = $!cursor.read-bytes($incl_len);
    $!packet-count++;

    # Timestamp as floating point epoch seconds
    my $ts = $!is-nanosecond
        ?? ($ts_sec.Num + ($ts_subsec.Num / 1000000000e0))
        !! ($ts_sec.Num + ($ts_subsec.Num / 1000000e0));

    return Sigil::Core::Packet.new(
        :raw($packet-bytes),
        :packet-id($!packet-count),
        :timestamp($ts),
        :wire-length($orig_len),
        :capture-length($incl_len),
        :interface($!filepath)
    );
}

# Slurp all packets from capture file into a list
method read-all(--> List) {
    my @packets;
    while self.read-next() -> $pkt {
        @packets.push($pkt);
    }
    return @packets.list;
}
