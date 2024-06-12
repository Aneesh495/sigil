# Sigil::Core::Layer - Protocol layer abstraction and decoded frame hierarchy
#
# Represents a single decoded protocol layer (header, fields, and payload)
# within a multi-layer packet stack.

unit package Sigil::Core;

use Sigil::Types;
use Sigil::Core::Field;

class Layer {
    has Str $.name is required;                     # Protocol identifier (e.g. "IPv4", "TCP")
    has Str $.display-name;                         # Human readable title (e.g. "Internet Protocol Version 4")
    has Int $.offset = 0;                           # Byte offset from start of packet
    has Int $.header-length = 0;                    # Header length in bytes
    has Int $.payload-length = 0;                   # Payload length in bytes
    has Buf $.raw-header;                           # Raw slice of wire header bytes
    has Buf $.raw-payload;                          # Raw slice of encapsulated payload bytes
    has FieldList $.fields;                         # Ordered list of parsed fields
    has DissectionStatus $.status = STATUS_OK;      # Parsing outcome status
    has Str $.status-detail = "";                   # Detail message for errors/warnings
    has Any $.next-protocol;                        # Selector value identifying inner payload protocol
    has Layer $.parent-layer;                       # Enclosing outer protocol layer
    has Layer $.child-layer;                        # Encapsulated inner protocol layer

    submethod BUILD(
        :$!name,
        :$!display-name = $!name,
        :$!offset = 0,
        :$!header-length = 0,
        :$!payload-length = 0,
        :$!raw-header = Buf.new,
        :$!raw-payload = Buf.new,
        :$!fields = FieldList.new,
        :$!status = STATUS_OK,
        :$!status-detail = "",
        :$!next-protocol = Nil,
        :$!parent-layer = Nil,
        :$!child-layer = Nil
    ) {}

    # Lookup field by selector key (e.g. "ip.src")
    method field(Str $key --> Field) {
        return $!fields.get($key);
    }

    # Retrieve native value of field by key
    method val(Str $key) {
        my $f = $!fields.get($key);
        return $f.defined ?? $f.value !! Nil;
    }

    # Add field to this layer's field collection
    method add-field(Field $f) {
        $!fields.add($f);
    }

    # Generate one-line summary of layer contents
    method summary(--> Str) {
        my @items;
        for $!fields.list -> $f {
            my $val = $f.format-value();
            if $val ne "" && $f.length-bytes > 0 {
                @items.push(sprintf("%s: %s", $f.name, $val));
            }
        }
        my $details = @items.elems > 0 ?? @items.head(4).join(", ") !! "length $!header-length";
        return sprintf("[%s] %s", $!name, $details);
    }

    # Generate multi-line hierarchical tree representation
    method to-tree-str(Int $indent = 0 --> Str) {
        my $pad = ' ' x $indent;
        my @lines;
        my $hdr = sprintf(
            "%sLayer %s (Offset: %d, Header: %d bytes, Payload: %d bytes)",
            $pad, $!display-name, $!offset, $!header-length, $!payload-length
        );
        @lines.push($hdr);
        if $!status != STATUS_OK {
            @lines.push(sprintf("%s  Status: %s (%s)", $pad, $!status.key, $!status-detail));
        }
        @lines.push($!fields.to-tree-str($indent + 2));
        return @lines.join("\n");
    }

    # Structured dictionary representation for JSON export
    method to-hash(--> Hash) {
        my %h = (
            name           => $!name,
            display_name   => $!display-name,
            offset         => $!offset,
            header_length  => $!header-length,
            payload_length => $!payload-length,
            status         => $!status.key,
            fields         => $!fields.to-hash-list()
        );
        %h<status_detail> = $!status-detail if $!status-detail ne "";
        if $!next-protocol.defined {
            %h<next_protocol> = ~$!next-protocol;
        }
        return %h;
    }
}
