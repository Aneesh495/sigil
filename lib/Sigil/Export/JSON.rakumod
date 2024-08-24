# Sigil::Export::JSON - Structured JSON and NDJSON serializer
#
# Generates standards-compliant JSON and newline-delimited JSON (NDJSON)
# for stream ingestion into log aggregators, SIEM platforms, and forensic pipelines.

unit class Sigil::Export::JSON;

use Sigil::Core::Packet;
use Sigil::Export::Formatter;

also does Sigil::Export::Formatter;

has Bool $.pretty = False;
has Bool $.ndjson = True;
has Int $.indent-spaces = 2;

# Pure Raku recursive JSON encoder
our sub to-json(Any $data, Int $depth = 0, Bool $pretty = False --> Str) is export {
    if !$data.defined {
        return "null";
    } elsif $data ~~ Bool {
        return $data ?? "true" !! "false";
    } elsif $data ~~ Int || $data ~~ Num || $data ~~ Rat {
        return ~$data;
    } elsif $data ~~ Str {
        my $escaped = $data;
        $escaped = $escaped.subst(/\\/, '\\\\', :g);
        $escaped = $escaped.subst(/\"/, '\\"', :g);
        $escaped = $escaped.subst(/\n/, '\\n', :g);
        $escaped = $escaped.subst(/\r/, '\\r', :g);
        $escaped = $escaped.subst(/\t/, '\\t', :g);
        return '"' ~ $escaped ~ '"';
    } elsif $data ~~ Positional {
        my @items = $data.list;
        return "[]" if @items.elems == 0;

        if $pretty {
            my $indent = " " x (($depth + 1) * 2);
            my $close-indent = " " x ($depth * 2);
            my @encoded = @items.map({ $indent ~ to-json($_, $depth + 1, $pretty) });
            return "[\n" ~ @encoded.join(",\n") ~ "\n" ~ $close-indent ~ "]";
        } else {
            my @encoded = @items.map({ to-json($_, $depth, False) });
            return "[" ~ @encoded.join(",") ~ "]";
        }
    } elsif $data ~~ Associative {
        my %h = $data.hash;
        return '{}' if %h.elems == 0;

        my @keys = %h.keys.sort;
        if $pretty {
            my $indent = " " x (($depth + 1) * 2);
            my $close-indent = " " x ($depth * 2);
            my @pairs = @keys.map(-> $k {
                my $v = %h{$k};
                $indent ~ '"' ~ $k ~ '": ' ~ to-json($v, $depth + 1, $pretty)
            });
            return "\{\n" ~ @pairs.join(",\n") ~ "\n" ~ $close-indent ~ "\}";
        } else {
            my @pairs = @keys.map(-> $k {
                my $v = %h{$k};
                '"' ~ $k ~ '":' ~ to-json($v, $depth, False)
            });
            return '{' ~ @pairs.join(",") ~ '}';
        }
    } else {
        return '"' ~ ~$data ~ '"';
    }
}

method header(--> Str) {
    return $!ndjson ?? "" !! "[\n";
}

method footer(--> Str) {
    return $!ndjson ?? "" !! "\n]";
}

# Format single packet
method format-packet(Sigil::Core::Packet $pkt --> Str) {
    my $h = $pkt.to-hash();
    return to-json($h, 0, $!pretty);
}
