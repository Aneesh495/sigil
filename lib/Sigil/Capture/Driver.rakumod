# Sigil::Capture::Driver - Abstract capture interface and packet ingestion role
#
# Provides consistent packet acquisition API across offline PCAP traces, live ring
# buffers, network taps, and IPC shared-memory workers.

unit role Sigil::Capture::Driver;

use Sigil::Core::Packet;

# Open or initialize capture source
method open(--> Bool) { ... }

# Retrieve next packet from driver; returns Nil on EOF or timeout
method next-packet(--> Sigil::Core::Packet) { ... }

# Capture statistics: packets captured, dropped, filtered
method stats(--> Hash) { ... }

# Close capture driver
method close() { ... }
