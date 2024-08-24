# Sigil::Export::Formatter - Base role for packet output serializations
#
# Declares standard formatting interface for terminal, forensic, and machine-readable
# export formats.

unit role Sigil::Export::Formatter;

use Sigil::Core::Packet;

# Header block prior to packet emission
method header(--> Str) { return ""; }

# Format an individual packet
method format-packet(Sigil::Core::Packet $pkt --> Str) { ... }

# Footer block following stream termination
method footer(--> Str) { return ""; }
