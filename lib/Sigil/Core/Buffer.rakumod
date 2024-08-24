# Sigil::Core::Buffer - Zero-allocation cursor and binary slice decoder
#
# Provides high-throughput binary cursor operations, bitfield extraction,
# network byte order conversions, and checkpointed lookahead parsing.

unit class Sigil::Core::Buffer;

use Sigil::Core::Error;
use Sigil::Types;

has Buf $.raw is required;
has Int $.offset = 0;
has Int $.bit-buffer = 0;
has Int $.bits-in-buffer = 0;
has @!checkpoints;

# Factory constructor from array of integers or byte buffer
multi method new(Buf $raw, Int :$offset = 0) {
    self.bless(:$raw, :$offset);
}

multi method new(@bytes, Int :$offset = 0) {
    self.bless(:raw(Buf.new(@bytes)), :$offset);
}

# Total capacity in bytes
method size(--> Int) {
    return $!raw.elems;
}

# Remaining bytes available from current cursor position
method remaining(--> Int) {
    my $rem = $!raw.elems - $!offset;
    return $rem > 0 ?? $rem !! 0;
}

# Check whether cursor has consumed entire buffer
method at-eof(--> Bool) {
    return $!offset >= $!raw.elems;
}

# Save current cursor state for backtracking (decontainerize values to snapshot scalars)
method checkpoint(--> Int) {
    @!checkpoints.push(($!offset.Int, $!bit-buffer.Int, $!bits-in-buffer.Int));
    return @!checkpoints.elems;
}

# Revert cursor state to most recently pushed checkpoint
method rollback() {
    if @!checkpoints.elems == 0 {
        die "Cannot rollback: checkpoint stack is empty";
    }
    my ($saved-offset, $saved-bb, $saved-bib) = @!checkpoints.pop;
    $!offset = $saved-offset;
    $!bit-buffer = $saved-bb;
    $!bits-in-buffer = $saved-bib;
}

# Discard most recent checkpoint upon successful parsing
method commit-checkpoint() {
    @!checkpoints.pop if @!checkpoints.elems > 0;
}

# Seek to absolute byte offset
method seek(Int $target-offset) {
    if $target-offset < 0 || $target-offset > $!raw.elems {
        X::Sigil::BufferOutOfBounds.new(
            :requested-offset($target-offset),
            :requested-length(0),
            :buffer-size($!raw.elems)
        ).throw;
    }
    $!offset = $target-offset;
    $!bit-buffer = 0;
    $!bits-in-buffer = 0;
}

# Advance cursor by relative delta
method skip(Int $delta) {
    self.seek($!offset + $delta);
}

# Ensure at least $bytes are remaining; throw structured exception otherwise
method require-bytes(Int $bytes) {
    if $!offset + $bytes > $!raw.elems {
        X::Sigil::BufferOutOfBounds.new(
            :requested-offset($!offset),
            :requested-length($bytes),
            :buffer-size($!raw.elems)
        ).throw;
    }
}

# Read unsigned 8-bit integer
method read-uint8(--> Int) {
    self.require-bytes(1);
    my $v = $!raw[$!offset];
    $!offset += 1;
    return $v;
}

# Read signed 8-bit integer
method read-int8(--> Int) {
    my $u = self.read-uint8();
    return $u >= 128 ?? $u - 256 !! $u;
}

# Read unsigned 16-bit integer in big-endian network byte order
method read-uint16-be(--> Int) {
    self.require-bytes(2);
    my $b0 = $!raw[$!offset];
    my $b1 = $!raw[$!offset + 1];
    $!offset += 2;
    return ($b0 +< 8) +| $b1;
}

# Read unsigned 16-bit integer in little-endian order
method read-uint16-le(--> Int) {
    self.require-bytes(2);
    my $b0 = $!raw[$!offset];
    my $b1 = $!raw[$!offset + 1];
    $!offset += 2;
    return ($b1 +< 8) +| $b0;
}

# Read unsigned 24-bit integer in big-endian network byte order
method read-uint24-be(--> Int) {
    self.require-bytes(3);
    my $b0 = $!raw[$!offset];
    my $b1 = $!raw[$!offset + 1];
    my $b2 = $!raw[$!offset + 2];
    $!offset += 3;
    return ($b0 +< 16) +| ($b1 +< 8) +| $b2;
}

# Read unsigned 32-bit integer in big-endian network byte order
method read-uint32-be(--> Int) {
    self.require-bytes(4);
    my $b0 = $!raw[$!offset];
    my $b1 = $!raw[$!offset + 1];
    my $b2 = $!raw[$!offset + 2];
    my $b3 = $!raw[$!offset + 3];
    $!offset += 4;
    return ($b0 +< 24) +| ($b1 +< 16) +| ($b2 +< 8) +| $b3;
}

# Read unsigned 32-bit integer in little-endian order
method read-uint32-le(--> Int) {
    self.require-bytes(4);
    my $b0 = $!raw[$!offset];
    my $b1 = $!raw[$!offset + 1];
    my $b2 = $!raw[$!offset + 2];
    my $b3 = $!raw[$!offset + 3];
    $!offset += 4;
    return ($b3 +< 24) +| ($b2 +< 16) +| ($b1 +< 8) +| $b0;
}

# Read unsigned 64-bit integer in big-endian network byte order
method read-uint64-be(--> Int) {
    self.require-bytes(8);
    my $hi = self.read-uint32-be();
    my $lo = self.read-uint32-be();
    return ($hi +< 32) +| $lo;
}

# Read unsigned 64-bit integer in little-endian order
method read-uint64-le(--> Int) {
    self.require-bytes(8);
    my $lo = self.read-uint32-le();
    my $hi = self.read-uint32-le();
    return ($hi +< 32) +| $lo;
}

# Fluent aliases for compact binary protocol code
method read-u8(--> Int) { return self.read-uint8(); }
method read-u16(--> Int) { return self.read-uint16-be(); }
method read-u16-le(--> Int) { return self.read-uint16-le(); }
method read-u32(--> Int) { return self.read-uint32-be(); }
method read-u32-le(--> Int) { return self.read-uint32-le(); }
method read-u64(--> Int) { return self.read-uint64-be(); }
method read-u64-le(--> Int) { return self.read-uint64-le(); }
method peek-u8(Int $delta = 0 --> Int) { return self.peek-uint8($delta); }
method is-eof(--> Bool) { return self.at-eof(); }

# Read arbitrary byte slice of specified length
method read-bytes(Int $count --> Buf) {
    self.require-bytes($count);
    my $slice = $!raw.subbuf($!offset, $count);
    $!offset += $count;
    return $slice;
}

# Read all remaining bytes from current cursor to end of buffer
method read-remaining(--> Buf) {
    my $rem = self.remaining();
    return $rem > 0 ?? self.read-bytes($rem) !! Buf.new;
}

# Peek at unsigned 8-bit integer without advancing cursor
method peek-uint8(Int $delta = 0 --> Int) {
    if $!offset + $delta >= $!raw.elems {
        return -1;
    }
    return $!raw[$!offset + $delta];
}

# Peek at unsigned 16-bit integer without advancing cursor
method peek-uint16-be(Int $delta = 0 --> Int) {
    if $!offset + $delta + 1 >= $!raw.elems {
        return -1;
    }
    my $b0 = $!raw[$!offset + $delta];
    my $b1 = $!raw[$!offset + $delta + 1];
    return ($b0 +< 8) +| $b1;
}

# Peek at byte slice without advancing cursor
method peek-bytes(Int $count, Int $delta = 0 --> Buf) {
    if $!offset + $delta + $count > $!raw.elems {
        return Buf.new;
    }
    return $!raw.subbuf($!offset + $delta, $count);
}

# Extract arbitrary bitfield across byte boundaries (up to 32 bits)
method read-bits(Int $count --> Int) {
    if $count <= 0 || $count > 32 {
        die "Bit read count must be between 1 and 32 bits (requested $count)";
    }

    while $!bits-in-buffer < $count {
        self.require-bytes(1);
        my $next-byte = $!raw[$!offset++];
        $!bit-buffer = ($!bit-buffer +< 8) +| $next-byte;
        $!bits-in-buffer += 8;
    }

    my $shift = $!bits-in-buffer - $count;
    my $mask = (1 +< $count) - 1;
    my $result = ($!bit-buffer +> $shift) +& $mask;
    $!bits-in-buffer -= $count;
    $!bit-buffer = $!bit-buffer +& ((1 +< $!bits-in-buffer) - 1);

    return $result;
}

# Align bit cursor to next whole byte boundary
method align-to-byte() {
    $!bit-buffer = 0;
    $!bits-in-buffer = 0;
}

# Read 6-byte IEEE 802 MAC address formatted as colon-separated hex
method read-mac(--> Str) {
    self.require-bytes(6);
    my @octets = $!raw.subbuf($!offset, 6).list;
    $!offset += 6;
    return @octets.map({ sprintf("%02x", $_) }).join(':');
}

# Read 4-byte IPv4 address formatted as dotted-decimal string
method read-ipv4(--> Str) {
    self.require-bytes(4);
    my @octets = $!raw.subbuf($!offset, 4).list;
    $!offset += 4;
    return @octets.join('.');
}

# Read 16-byte IPv6 address formatted as canonical colon-separated hex
method read-ipv6(--> Str) {
    self.require-bytes(16);
    my @words;
    for 0..7 -> $i {
        my $idx = $!offset + ($i * 2);
        my $w = ($!raw[$idx] +< 8) +| $!raw[$idx + 1];
        @words.push(sprintf("%x", $w));
    }
    $!offset += 16;
    return @words.join(':');
}

# Read ASCII string of specified length
method read-ascii(Int $length --> Str) {
    my $bytes = self.read-bytes($length);
    return $bytes.decode('ascii');
}

# Read null-terminated C string
method read-cstring(Int $max-len = 256 --> Str) {
    my @chars;
    my $consumed = 0;
    while $!offset < $!raw.elems && $consumed < $max-len {
        my $b = self.read-uint8();
        $consumed++;
        last if $b == 0;
        @chars.push($b.chr);
    }
    return @chars.join('');
}

# Produce formatted multi-line hex dump of buffer contents
method hex-dump(Int :$offset = 0, Int :$length = $!raw.elems - $offset, Int :$width = 16 --> Str) {
    my $target-len = min($length, $!raw.elems - $offset);
    return "" if $target-len <= 0;

    my @lines;
    my $end = $offset + $target-len;
    my $curr = $offset;

    while $curr < $end {
        my $line-len = min($width, $end - $curr);
        my @slice = $!raw.subbuf($curr, $line-len).list;

        # Hex representation
        my $hex-part = @slice.map({ sprintf("%02x", $_) }).join(' ');
        if $line-len < $width {
            my $pad = ($width - $line-len) * 3;
            $hex-part ~= ' ' x $pad;
        }

        # Printable ASCII representation
        my $ascii-part = @slice.map({
            32 <= $_ <= 126 ?? $_.chr !! '.'
        }).join('');

        @lines.push(sprintf("%08x  %-*s |%s|", $curr, $width * 3, $hex-part, $ascii-part));
        $curr += $width;
    }

    return @lines.join("\n");
}
