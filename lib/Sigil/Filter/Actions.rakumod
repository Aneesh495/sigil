# Sigil::Filter::Actions - AST builder action class for packet filter grammar
#
# Transforms match trees into executable Abstract Syntax Tree nodes.

unit class Sigil::Filter::Actions;

use Sigil::Filter::AST;

method TOP($/) {
    make $<or-expr>.made;
}

method or-expr($/) {
    my @terms = $<and-expr>.map(*.made);
    my $node = @terms[0];
    for @terms.tail(*-1) -> $next-term {
        $node = Sigil::Filter::AST::OrNode.new(:left($node), :right($next-term));
    }
    make $node;
}

method and-expr($/) {
    my @terms = $<not-expr>.map(*.made);
    my $node = @terms[0];
    for @terms.tail(*-1) -> $next-term {
        $node = Sigil::Filter::AST::AndNode.new(:left($node), :right($next-term));
    }
    make $node;
}

method not-expr($/) {
    if $<not-expr> {
        make Sigil::Filter::AST::NotNode.new(:child($<not-expr>.made));
    } else {
        make $<primary-expr>.made;
    }
}

method primary-expr($/) {
    if $<or-expr> {
        make $<or-expr>.made;
    } elsif $<cidr-pred> {
        make $<cidr-pred>.made;
    } elsif $<contains-pred> {
        make $<contains-pred>.made;
    } elsif $<in-set-pred> {
        make $<in-set-pred>.made;
    } elsif $<compare-pred> {
        make $<compare-pred>.made;
    } elsif $<proto-pred> {
        make $<proto-pred>.made;
    }
}

method proto-pred($/) {
    make Sigil::Filter::AST::ProtoNode.new(:proto-name(~$<proto-name>));
}

method compare-pred($/) {
    make Sigil::Filter::AST::CompareNode.new(
        :field-key(~$<field-key>),
        :op(~$<comp-op>),
        :target-val($<value>.made)
    );
}

method contains-pred($/) {
    make Sigil::Filter::AST::StringContainsNode.new(
        :field-key(~$<field-key>),
        :substring($<string-val>.made)
    );
}

method in-set-pred($/) {
    make Sigil::Filter::AST::SetInNode.new(
        :field-key(~$<field-key>),
        :set-values($<value-list>.made)
    );
}

method value-list($/) {
    make $<value>.map(*.made).Array;
}

method cidr-pred($/) {
    make Sigil::Filter::AST::CIDRNode.new(
        :field-key(~$<field-key>),
        :cidr(~$<cidr-val>)
    );
}

method value($/) {
    if $<string-val> {
        make $<string-val>.made;
    } elsif $<hex-num> {
        make $<hex-num>.made;
    } elsif $<ip-addr-val> {
        make ~$<ip-addr-val>;
    } elsif $<dec-num> {
        make $<dec-num>.made;
    }
}

method hex-num($/) {
    make :16(~$/.substr(2));
}

method dec-num($/) {
    make $/.Int;
}

method string-val($/) {
    make ~$0;
}
