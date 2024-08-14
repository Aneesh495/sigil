# Sigil::Filter::Engine - Packet filtering runtime and stream evaluator
#
# Evaluates compiled filter predicates against packet streams and records matching metrics.

unit class Sigil::Filter::Engine;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Filter::Compiler;

has Sigil::Filter::Compiler $.compiler;
has Str $.current-filter = "";
has Sub $!compiled-predicate;
has Int $.packets-evaluated = 0;
has Int $.packets-matched = 0;
has Int $.packets-dropped = 0;

submethod TWEAK() {
    $!compiler //= Sigil::Filter::Compiler.new;
    self.set-filter($!current-filter);
}

# Update active filter expression and recompile predicate
method set-filter(Str $expr) {
    $!current-filter = $expr;
    $!compiled-predicate = $!compiler.compile($expr);
}

# Evaluate packet against active filter
method matches(Sigil::Core::Packet $pkt --> Bool) {
    $!packets-evaluated++;
    my $result = $!compiled-predicate($pkt);
    if $result {
        $!packets-matched++;
    } else {
        $!packets-dropped++;
    }
    return $result;
}

# Filter list of packets in-memory
method filter-list(@packets) {
    my @matched;
    for @packets -> $p {
        @matched.push($p) if self.matches($p);
    }
    return @matched;
}

# Telemetry stats
method stats(--> Hash) {
    return {
        filter_expression => $!current-filter,
        packets_evaluated => $!packets-evaluated,
        packets_matched   => $!packets-matched,
        packets_dropped   => $!packets-dropped,
        match_rate        => $!packets-evaluated > 0 ?? ($!packets-matched / $!packets-evaluated) !! 0e0
    };
}
