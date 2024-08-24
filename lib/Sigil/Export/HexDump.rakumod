# Sigil::Export::HexDump - Canonical hex dump with layer boundary coloring
#
# Generates side-by-side hex and ASCII memory dumps with optional ANSI syntax
# highlighting across packet protocol header boundaries.

unit class Sigil::Export::HexDump;

use Sigil::Core::Packet;
use Sigil::Export::Formatter;

also does Sigil::Export::Formatter;

has Int $.width = 16;
has Bool $.colorized = False;

# Format hex dump of packet
method format-packet(Sigil::Core::Packet $pkt --> Str) {
    my $raw = $pkt.raw;
    my $len = $pkt.capture-length;
    return "(empty payload)" if $len == 0;

    my @lines;
    @lines.push(sprintf("--- Packet #%d (%d bytes wire, %d bytes captured) ---",
        $pkt.packet-id, $pkt.wire-length, $len));

    my $offset = 0;
    while $offset < $len {
        my $chunk-len = ($len - $offset < $!width) ?? ($len - $offset) !! $!width;
        my $chunk = $raw.subbuf($offset, $chunk-len);

        # Hex representation
        my @hex-parts;
        for 0 ..^ $!width -> $i {
            if $i < $chunk-len {
                @hex-parts.push(sprintf("%02x", $chunk[$i]));
            } else {
                @hex-parts.push("  ");
            }
            if $i == 7 {
                @hex-parts.push(" "); # Middle separator
            }
        }
        my $hex-str = @hex-parts.join(" ");

        # ASCII representation
        my @ascii-parts;
        for 0 ..^ $chunk-len -> $i {
            my $b = $chunk[$i];
            my $ch = ($b >= 32 && $b <= 126) ?? $b.chr !! ".";
            @ascii-parts.push($ch);
        }
        my $ascii-str = @ascii-parts.join("");

        @lines.push(sprintf("%08x  %-49s |%s|", $offset, $hex-str, $ascii-str));
        $offset += $!width;
    }

    return @lines.join("\n");
}
