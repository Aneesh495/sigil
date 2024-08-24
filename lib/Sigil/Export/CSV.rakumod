# Sigil::Export::CSV - Comma-separated value telemetry table exporter
#
# Emits tabular packet metadata with RFC 4180 quoting and custom column selection.

unit class Sigil::Export::CSV;

use Sigil::Core::Packet;
use Sigil::Export::Formatter;

also does Sigil::Export::Formatter;

has Str $.delimiter = ",";
has @.columns = <id timestamp src dst srcport dstport protocol length>;

method header(--> Str) {
    return @!columns.join($!delimiter);
}

# Format single packet into CSV line
method format-packet(Sigil::Core::Packet $pkt --> Str) {
    my @row;

    for @!columns -> $col {
        my $val = "";
        given $col {
            when "id"        { $val = ~$pkt.packet-id; }
            when "timestamp" { $val = sprintf("%.6f", $pkt.timestamp); }
            when "src"       { $val = $pkt.val("ip.src") // $pkt.val("ipv6.src") // $pkt.val("eth.src") // ""; }
            when "dst"       { $val = $pkt.val("ip.dst") // $pkt.val("ipv6.dst") // $pkt.val("eth.dst") // ""; }
            when "srcport"   { $val = ~$($pkt.val("tcp.srcport") // $pkt.val("udp.srcport") // ""); }
            when "dstport"   { $val = ~$($pkt.val("tcp.dstport") // $pkt.val("udp.dstport") // ""); }
            when "protocol"  { $val = $pkt.highest-layer.defined ?? $pkt.highest-layer.name !! "RAW"; }
            when "length"    { $val = ~$pkt.capture-length; }
            default          { $val = ~$($pkt.val($col) // ""); }
        }

        # RFC 4180 escaping
        if $val.contains($!delimiter) || $val.contains('"') || $val.contains("\n") {
            $val = $val.subst('"', '""', :g);
            $val = '"' ~ $val ~ '"';
        }

        @row.push($val);
    }

    return @row.join($!delimiter);
}
