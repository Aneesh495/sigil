# Sigil::Core::Packet - Captured network frame container and multi-layer stack
#
# Provides packet metadata, layered protocol representation, deep field lookup,
# and structured export serialization.

unit package Sigil::Core;

use Sigil::Types;
use Sigil::Core::Layer;
use Sigil::Core::Buffer;

class Packet {
    has Int $.packet-id = 0;                        # Monotonic capture sequence number
    has Num $.timestamp = 0e0;                      # Fractional UNIX epoch seconds
    has Int $.wire-length = 0;                      # Frame length transmitted on physical wire
    has Int $.capture-length = 0;                   # Frame length saved in capture buffer
    has Str $.interface = "unknown";                # Capture network interface device name
    has PacketDirection $.direction = DIR_UNKNOWN;  # Directionality relative to vantage point
    has Buf $.raw is required;                      # Raw captured frame payload
    has Layer @!layers;                             # Decoded protocol layer stack
    has %!annotations;                              # User forensic tags and metadata markers
    has DissectionStatus $.status = STATUS_OK;      # Overall dissection status outcome

    submethod BUILD(
        :$!raw,
        :$!packet-id = 0,
        :$!timestamp = 0e0,
        :$!wire-length = $!raw.elems,
        :$!capture-length = $!raw.elems,
        :$!interface = "unknown",
        :$!direction = DIR_UNKNOWN,
        :$!status = STATUS_OK
    ) {}

    # Check whether snaplen truncation occurred
    method is-truncated(--> Bool) {
        return $!capture-length < $!wire-length;
    }

    # Packet captured length convenience accessor
    method length(--> Int) {
        return $!capture-length;
    }

    # Payload buffer of the highest decoded layer
    method payload(--> Buf) {
        my $top = self.highest-layer;
        return ($top.defined && $top.raw-payload.defined) ?? $top.raw-payload !! Buf.new;
    }

    # Push newly decoded protocol layer onto stack and link parent/child relations
    method push-layer(Layer $new-layer) {
        if @!layers.elems > 0 {
            my $prev-layer = @!layers[*-1];
            # Note: in Raku, attributes can be bound or set if needed
        }
        @!layers.push($new-layer);
    }

    # Number of decoded protocol layers
    method layer-count(--> Int) {
        return @!layers.elems;
    }

    # Retrieve all layers
    method layers() {
        return @!layers;
    }

    # Retrieve specific layer by protocol name (case-insensitive)
    method layer(Str $proto-name --> Layer) {
        my $target = $proto-name.lc;
        for @!layers -> $l {
            return $l if $l.name.lc eq $target;
        }
        return Nil;
    }

    # Check whether protocol exists anywhere in the stack
    method has-layer(Str $proto-name --> Bool) {
        return self.layer($proto-name).defined;
    }

    # Outermost (highest) application/transport layer
    method highest-layer(--> Layer) {
        return @!layers.elems > 0 ?? @!layers[*-1] !! Nil;
    }

    # Lowest (link) layer
    method link-layer(--> Layer) {
        return @!layers.elems > 0 ?? @!layers[0] !! Nil;
    }

    # Deep field lookup across all layers in the stack (e.g. "ip.src", "tcp.dstport")
    method val(Str $key) {
        for @!layers -> $l {
            my $v = $l.val($key);
            return $v if $v.defined;
        }
        return Nil;
    }

    # Add forensic annotation
    method annotate(Str $tag, Str $comment) {
        %!annotations{$tag} = $comment;
    }

    # Retrieve annotations hash
    method annotations(--> Hash) {
        return %!annotations;
    }

    # Formatted one-line summary
    method summary(--> Str) {
        my $src = self.val('ip.src') // self.val('eth.src') // "unknown";
        my $dst = self.val('ip.dst') // self.val('eth.dst') // "unknown";
        my $proto = self.highest-layer.defined ?? self.highest-layer.name !! "RAW";
        my $info = self.highest-layer.defined ?? self.highest-layer.summary !! sprintf("%d bytes", $!capture-length);

        return sprintf(
            "#%-5d %10.6f  %-18s -> %-18s  %-8s  Len=%-5d  %s",
            $!packet-id, $!timestamp, $src, $dst, $proto, $!capture-length, $info
        );
    }

    # Formatted multi-line hierarchical dissection tree
    method to-tree-str(--> Str) {
        my @lines;
        @lines.push(sprintf(
            "Frame %d: %d bytes on wire, %d bytes captured on interface %s",
            $!packet-id, $!wire-length, $!capture-length, $!interface
        ));
        for @!layers -> $l {
            @lines.push($l.to-tree-str(2));
        }
        return @lines.join("\n");
    }

    # Multi-line hex dump of raw frame bytes
    method hex-dump(Int :$width = 16 --> Str) {
        my $buf = Sigil::Core::Buffer.new($!raw);
        return $buf.hex-dump(:width($width));
    }

    # Structured dictionary representation for JSON export
    method to-hash(--> Hash) {
        my @layer-hashes = @!layers.map(*.to-hash());
        my %h = (
            packet_id      => $!packet-id,
            timestamp      => $!timestamp,
            wire_length    => $!wire-length,
            capture_length => $!capture-length,
            interface      => $!interface,
            direction      => $!direction.key,
            status         => $!status.key,
            layers         => @layer-hashes
        );
        %h<annotations> = %!annotations if %!annotations.elems > 0;
        return %h;
    }
}
