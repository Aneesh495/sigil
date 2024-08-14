# Sigil::Filter::Compiler - Compilation and closure generation for filter AST
#
# Compiles declarative filter AST expressions into high-speed executable closures,
# maintaining an internal compiled predicate cache.

unit class Sigil::Filter::Compiler;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Error;
use Sigil::Filter::Grammar;
use Sigil::Filter::Actions;
use Sigil::Filter::AST;

has %!cache; # Filter expression string -> compiled closure

# Compile filter expression string into executable closure
method compile(Str $expr --> Sub) {
    my $trimmed = $expr.trim;
    return sub (Sigil::Core::Packet $p --> Bool) { True } if $trimmed eq "" || $trimmed eq "all";

    if %!cache{$trimmed}:exists {
        return %!cache{$trimmed};
    }

    my $actions = Sigil::Filter::Actions.new;
    my $match = Sigil::Filter::Grammar.parse($trimmed, :$actions);

    if !$match {
        X::Sigil::FilterSyntaxError.new(
            :filter-expression($trimmed),
            :position(0),
            :error-detail("Failed to parse filter syntax")
        ).throw;
    }

    my Sigil::Filter::AST::Node $ast = $match.made;

    # Generate optimized closure evaluating compiled AST
    my $compiled-sub = sub (Sigil::Core::Packet $pkt --> Bool) {
        return $ast.evaluate($pkt);
    };

    %!cache{$trimmed} = $compiled-sub;
    return $compiled-sub;
}

# Clear cached compiled filter closures
method clear-cache() {
    %!cache = ();
}
