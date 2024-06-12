# Sigil::Core::Field - Protocol header field descriptor and tree hierarchy
#
# Provides strongly typed field representations, bitmask formatters,
# and hierarchical tree formatting for deep packet inspection.

unit package Sigil::Core;

use Sigil::Types;

# Base field representation
class Field {
    has Str $.name is required;          # Human readable name (e.g. "Source Port")
    has Str $.key is required;           # Filter engine selector key (e.g. "tcp.srcport")
    has Int $.offset-bytes = 0;          # Byte offset within containing layer
    has Int $.length-bytes = 0;          # Length in bytes occupied on wire
    has Any $.value;                     # Parsed native value
    has Buf $.raw;                       # Raw slice of wire bytes
    has Str $.description = "";          # Optional RFC/specification note

    method format-value(--> Str) {
        return $!value.defined ?? ~$!value !! "";
    }

    method to-hash(--> Hash) {
        my %h = (
            name   => $!name,
            key    => $!key,
            offset => $!offset-bytes,
            length => $!length-bytes,
            value  => $!value,
            repr   => self.format-value()
        );
        %h<description> = $!description if $!description ne "";
        return %h;
    }
}

# Integer field with configurable radix representation
class IntField is Field {
    has Str $.radix = 'dec'; # 'dec', 'hex', 'bin'
    has Int $.bit-width = 32;

    method format-value(--> Str) {
        my $val = self.value;
        return "" unless $val.defined;
        my $v = $val.Int;
        return do given $!radix {
            when 'hex' { sprintf("0x%0*x", ($!bit-width / 4).ceiling, $v) }
            when 'bin' { sprintf("0b%0*b", $!bit-width, $v) }
            default    { ~$v }
        }
    }
}

# Sub-byte bitfield descriptor
class BitField is Field {
    has Int $.bit-offset is required;   # Offset in bits from byte boundary
    has Int $.bit-length is required;   # Length in bits (1 to 32)

    method format-value(--> Str) {
        my $val = self.value;
        return "" unless $val.defined;
        return sprintf("%d (bits %d..%d)", $val, $!bit-offset, $!bit-offset + $!bit-length - 1);
    }
}

# Boolean flag field representing single bit or bitmask
class FlagField is Field {
    has Int $.mask is required;
    has Bool $.is-set is required;

    method format-value(--> Str) {
        return $!is-set ?? "Set (1)" !! "Not set (0)";
    }
}

# Symbolic enumeration field mapping raw numeric code to protocol name
class EnumField is Field {
    has %.name-map;

    method format-value(--> Str) {
        my $val = self.value;
        return "" unless $val.defined;
        my $code = $val.Int;
        if %!name-map{$code}:exists {
            return sprintf("%s (%d)", %!name-map{$code}, $code);
        }
        return sprintf("Unknown (%d)", $code);
    }
}

# Network address field (MAC, IPv4, IPv6)
class AddressField is Field {
    has Str $.address-type = 'ipv4'; # 'mac', 'ipv4', 'ipv6'

    method format-value(--> Str) {
        my $val = self.value;
        return $val.defined ?? ~$val !! "";
    }
}

# String field (ASCII or UTF-8)
class StringField is Field {
    has Str $.encoding = 'utf-8';

    method format-value(--> Str) {
        my $val = self.value;
        return $val.defined ?? '"' ~ $val ~ '"' !! '""';
    }
}

# Raw opaque bytes field
class BytesField is Field {
    method format-value(--> Str) {
        my $raw = self.raw;
        return "" unless $raw.defined;
        my $limit = min($raw.elems, 16);
        my $hex = $raw.subbuf(0, $limit).list.map({ sprintf("%02x", $_) }).join(' ');
        if $raw.elems > $limit {
            $hex ~= sprintf(" ... [%d bytes total]", $raw.elems);
        }
        return $hex;
    }
}

# Ordered collection of fields for a protocol layer
class FieldList {
    has Field @!fields;
    has %!index; # key -> Field mapping for fast filter lookups

    method add(Field $f) {
        @!fields.push($f);
        %!index{$f.key} = $f;
    }

    method get(Str $key --> Any) {
        return %!index{$key};
    }

    method has-key(Str $key --> Bool) {
        return %!index{$key}:exists;
    }

    method elems(--> Int) {
        return @!fields.elems;
    }

    method list() {
        return @!fields;
    }

    method to-tree-str(Int $indent = 0 --> Str) {
        my $pad = ' ' x $indent;
        my @lines;
        for @!fields -> $f {
            my $val-str = $f.format-value();
            @lines.push(sprintf("%s%-28s: %s", $pad, $f.name, $val-str));
        }
        return @lines.join("\n");
    }

    method to-hash-list(--> Array) {
        my @result;
        for @!fields -> $f {
            @result.push($f.to-hash());
        }
        return @result;
    }
}
