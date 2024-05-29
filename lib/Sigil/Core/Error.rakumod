# Sigil::Core::Error - Structured exception hierarchy for protocol dissection
#
# Implements precise error reporting with packet offset markers, expected
# vs actual byte counts, and actionable diagnostic contexts.

unit package Sigil::Core;

# Base exception role for all Sigil domain errors
role X::Sigil is Exception {
    has Str $.message = "Generic Sigil error encountered";
    method message() { $!message }
}

# Buffer read past available payload boundary
class X::Sigil::BufferOutOfBounds does X::Sigil {
    has Int $.requested-offset;
    has Int $.requested-length;
    has Int $.buffer-size;

    method message() {
        sprintf(
            "Buffer read out of bounds: attempted to read %d bytes at offset %d, but buffer size is %d bytes",
            $!requested-length, $!requested-offset, $!buffer-size
        );
    }
}

# Packet payload is truncated relative to wire header lengths
class X::Sigil::TruncatedPacket does X::Sigil {
    has Str $.protocol;
    has Int $.expected-bytes;
    has Int $.available-bytes;

    method message() {
        sprintf(
            "Truncated %s header or payload: expected at least %d bytes, but only %d bytes available",
            $!protocol, $!expected-bytes, $!available-bytes
        );
    }
}

# Protocol checksum failure detected during header verification
class X::Sigil::ChecksumMismatch does X::Sigil {
    has Str $.protocol;
    has Int $.computed;
    has Int $.actual;

    method message() {
        sprintf(
            "%s checksum mismatch: packet header specified 0x%04x, but computed checksum is 0x%04x",
            $!protocol, $!actual, $!computed
        );
    }
}

# Malformed protocol field syntax or invalid reserved bits
class X::Sigil::MalformedHeader does X::Sigil {
    has Str $.protocol;
    has Str $.field-name;
    has Str $.reason;
    has Int $.offset;

    method message() {
        sprintf(
            "Malformed %s header at offset %d in field '%s': %s",
            $!protocol, $!offset, $!field-name, $!reason
        );
    }
}

# Unsupported layer or unknown protocol selector value
class X::Sigil::UnsupportedProtocol does X::Sigil {
    has Str $.parent-protocol;
    has Str $.selector-field;
    has Int $.selector-value;

    method message() {
        sprintf(
            "Unsupported protocol under %s (selector %s = 0x%x)",
            $!parent-protocol, $!selector-field, $!selector-value
        );
    }
}

# Filter DSL compilation or parse failure
class X::Sigil::FilterSyntaxError does X::Sigil {
    has Str $.filter-expression;
    has Int $.position;
    has Str $.error-detail;

    method message() {
        sprintf(
            "Filter compilation error at character position %d: %s (in expression: '%s')",
            $!position, $!error-detail, $!filter-expression
        );
    }
}

# Flow reassembly anomaly or window buffer exhaustion
class X::Sigil::FlowReassemblyError does X::Sigil {
    has Str $.session-key;
    has Str $.reason;
    has Int $.sequence-number;

    method message() {
        sprintf(
            "TCP flow reassembly error for session [%s] at seq %u: %s",
            $!session-key, $!sequence-number, $!reason
        );
    }
}
