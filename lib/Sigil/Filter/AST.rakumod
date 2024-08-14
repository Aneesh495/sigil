# Sigil::Filter::AST - Abstract Syntax Tree nodes for filter expressions
#
# Represents parsed filter predicates, relational comparisons, CIDR containment,
# protocol presence tests, and boolean algebraic compositions.

unit package Sigil::Filter::AST;

use Sigil::Types;
use Sigil::Core::Packet;

# Base AST Node
role Node {
    method evaluate(Sigil::Core::Packet $pkt --> Bool) { ... }
}

# Protocol presence node (e.g. "tcp", "http", "dns")
class ProtoNode does Node {
    has Str $.proto-name is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        return $pkt.has-layer($!proto-name);
    }
}

# Relational comparison node (e.g. "tcp.dstport == 443", "ip.ttl < 64")
class CompareNode does Node {
    has Str $.field-key is required;
    has Str $.op is required; # '==', '!=', '<', '<=', '>', '>='
    has Any $.target-val is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        my $actual = $pkt.val($!field-key);
        return False unless $actual.defined;

        my $target = $!target-val;

        # String vs Numeric comparison
        if $actual ~~ Numeric && $target ~~ Numeric {
            return do given $!op {
                when '==' { $actual == $target }
                when '!=' { $actual != $target }
                when '<'  { $actual < $target }
                when '<=' { $actual <= $target }
                when '>'  { $actual > $target }
                when '>=' { $actual >= $target }
                default   { False }
            }
        } else {
            my $s-act = ~$actual;
            my $s-tgt = ~$target;
            return do given $!op {
                when '==' { $s-act eq $s-tgt }
                when '!=' { $s-act ne $s-tgt }
                default   { False }
            }
        }
    }
}

# String contains node (e.g. "http.host contains 'github'")
class StringContainsNode does Node {
    has Str $.field-key is required;
    has Str $.substring is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        my $actual = $pkt.val($!field-key);
        return False unless $actual.defined;
        return (~$actual).contains($!substring);
    }
}

# Set membership node (e.g. "tcp.dstport in [80, 443, 8080]")
class SetInNode does Node {
    has Str $.field-key is required;
    has @.set-values is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        my $actual = $pkt.val($!field-key);
        return False unless $actual.defined;

        for @!set-values -> $v {
            if $actual ~~ Numeric && $v ~~ Numeric {
                return True if $actual == $v;
            } else {
                return True if ~$actual eq ~$v;
            }
        }
        return False;
    }
}

# IPv4 CIDR matching node (e.g. "ip.src in 192.168.0.0/16")
class CIDRNode does Node {
    has Str $.field-key is required;
    has Str $.cidr is required;
    has uint32 $!network-int;
    has uint32 $!netmask-int;

    submethod BUILD(:$!field-key, :$!cidr) {
        my ($ip-part, $prefix-len) = $!cidr.split('/');
        my @octets = $ip-part.split('.').map(*.Int);
        $!network-int = (@octets[0] +< 24) +| (@octets[1] +< 16) +| (@octets[2] +< 8) +| @octets[3];
        my $bits = $prefix-len.Int;
        $!netmask-int = $bits == 0 ?? 0 !! ((0xFFFFFFFF +< (32 - $bits)) +& 0xFFFFFFFF);
        $!network-int = $!network-int +& $!netmask-int;
    }

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        my $actual = $pkt.val($!field-key);
        return False unless $actual.defined;
        return False unless $actual ~~ /^\d+ \. \d+ \. \d+ \. \d+$/;

        my @octets = $actual.split('.').map(*.Int);
        my uint32 $act-int = (@octets[0] +< 24) +| (@octets[1] +< 16) +| (@octets[2] +< 8) +| @octets[3];

        return ($act-int +& $!netmask-int) == $!network-int;
    }
}

# Boolean AND node
class AndNode does Node {
    has Node $.left is required;
    has Node $.right is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        return $!left.evaluate($pkt) && $!right.evaluate($pkt);
    }
}

# Boolean OR node
class OrNode does Node {
    has Node $.left is required;
    has Node $.right is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        return $!left.evaluate($pkt) || $!right.evaluate($pkt);
    }
}

# Boolean NOT node
class NotNode does Node {
    has Node $.child is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        return !$!child.evaluate($pkt);
    }
}

# Boolean literal node (True / False)
class BoolNode does Node {
    has Bool $.value is required;

    method evaluate(Sigil::Core::Packet $pkt --> Bool) {
        return $!value;
    }
}
