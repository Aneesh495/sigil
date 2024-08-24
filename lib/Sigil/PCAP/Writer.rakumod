# Sigil::PCAP::Writer - Pure-Raku libpcap capture file generator
#
# Serializes Sigil::Core::Packet collections into standard binary PCAP capture
# files compatible with tcpdump, Wireshark, and forensic toolchains.

unit class Sigil::PCAP::Writer;

use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::PCAP::Header;

has Sigil::PCAP::GlobalHeader $.header;
has Buf $.buffer;
has Bool $.is-little-endian = True;
has Bool $.is-nanosecond = False;
has Int $.packet-count = 0;

submethod BUILD(
    Bool :$!is-little-endian = True,
    Bool :$!is-nanosecond = False,
    Int :$snaplen = 65535,
    Int :$linktype = LINKTYPE_ETHERNET
) {
    my $magic = $!is-nanosecond ?? PCAP_MAGIC_NANO_BE !! PCAP_MAGIC_MICRO_BE;
    $!header = Sigil::PCAP::GlobalHeader.new(
        :$magic,
        :version-major(2),
        :version-minor(4),
        :$snaplen,
        :$linktype,
        :$!is-little-endian,
        :$!is-nanosecond
    );
    $!buffer = $!header.to-bytes();
}

# Append a single packet to capture buffer
method write-packet(Sigil::Core::Packet $pkt) {
    $!packet-count++;
    my $ts = $pkt.timestamp;
    my $ts-sec = $ts.Int;
    my $ts-subsec = $!is-nanosecond
        ?? (($ts - $ts-sec) * 1000000000e0).round.Int
        !! (($ts - $ts-sec) * 1000000e0).round.Int;

    my $raw = $pkt.raw;
    my $incl-len = $pkt.capture-length;
    my $orig-len = $pkt.wire-length;

    my @rec-header;
    if $!is-little-endian {
        @rec-header.push($ts-sec +& 0xFF, ($ts-sec +> 8) +& 0xFF, ($ts-sec +> 16) +& 0xFF, ($ts-sec +> 24) +& 0xFF);
        @rec-header.push($ts-subsec +& 0xFF, ($ts-subsec +> 8) +& 0xFF, ($ts-subsec +> 16) +& 0xFF, ($ts-subsec +> 24) +& 0xFF);
        @rec-header.push($incl-len +& 0xFF, ($incl-len +> 8) +& 0xFF, ($incl-len +> 16) +& 0xFF, ($incl-len +> 24) +& 0xFF);
        @rec-header.push($orig-len +& 0xFF, ($orig-len +> 8) +& 0xFF, ($orig-len +> 16) +& 0xFF, ($orig-len +> 24) +& 0xFF);
    } else {
        @rec-header.push(($ts-sec +> 24) +& 0xFF, ($ts-sec +> 16) +& 0xFF, ($ts-sec +> 8) +& 0xFF, $ts-sec +& 0xFF);
        @rec-header.push(($ts-subsec +> 24) +& 0xFF, ($ts-subsec +> 16) +& 0xFF, ($ts-subsec +> 8) +& 0xFF, $ts-subsec +& 0xFF);
        @rec-header.push(($incl-len +> 24) +& 0xFF, ($incl-len +> 16) +& 0xFF, ($incl-len +> 8) +& 0xFF, $incl-len +& 0xFF);
        @rec-header.push(($orig-len +> 24) +& 0xFF, ($orig-len +> 16) +& 0xFF, ($orig-len +> 8) +& 0xFF, $orig-len +& 0xFF);
    }

    $!buffer.append(@rec-header);
    $!buffer.append($raw.subbuf(0, $incl-len));
}

# Write complete packet list to a file path
method save-file(Str $path) {
    $path.IO.spurt($!buffer, :bin);
}

# Retrieve full binary capture buffer
method to-bytes(--> Buf) {
    return $!buffer;
}
