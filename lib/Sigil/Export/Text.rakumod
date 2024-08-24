# Sigil::Export::Text - Terminal one-liner and hierarchical tree formatter
#
# Emits Wireshark-style columnar packet listings or multi-line tree expansions.

unit class Sigil::Export::Text;

use Sigil::Core::Packet;
use Sigil::Export::Formatter;

also does Sigil::Export::Formatter;

has Bool $.show-tree = False;
has Bool $.colorized = False;

# Column headers
method header(--> Str) {
    return self.show-tree ?? "" !! sprintf(
        "%-6s %10s  %-18s -> %-18s  %-8s  %-6s  %s\n%s",
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info",
        "-" x 100
    );
}

# Format a single packet
method format-packet(Sigil::Core::Packet $pkt --> Str) {
    if $!show-tree {
        my $tree = $pkt.to-tree-str();
        return $tree ~ "\n" ~ ("=" x 80);
    } else {
        return $pkt.summary();
    }
}
