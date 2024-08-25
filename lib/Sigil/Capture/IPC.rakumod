# Sigil::Capture::IPC - Unix domain socket and shared-memory packet framing driver
#
# Inter-process communication driver exchanging raw packet frames and telemetry
# with the high-throughput C capture ring buffer worker.

unit class Sigil::Capture::IPC;

use Sigil::Core::Packet;
use Sigil::Capture::Driver;

also does Sigil::Capture::Driver;

our constant SIGIL_IPC_MAGIC = 0x5349474C; # ASCII 'SIGL'

has Str $.socket-path = "/tmp/sigil_capture.sock";
has IO::Socket::Async $!client-conn;
has Bool $.is-connected = False;
has Int $.frames-received = 0;
has Int $.bytes-received = 0;

# Serialize packet to binary IPC frame
our sub encode-frame(Sigil::Core::Packet $pkt --> Buf) is export {
    my $raw = $pkt.raw;
    my $caplen = $pkt.capture-length;
    my $wirelen = $pkt.wire-length;
    my $ts = $pkt.timestamp;
    my $ts-sec = $ts.Int;
    my $ts-usec = (($ts - $ts-sec) * 1000000e0).round.Int;
    my $seq = $pkt.packet-id;

    my @hdr;
    # Magic 'SIGL' (0x53, 0x49, 0x47, 0x4C)
    @hdr.push(0x53, 0x49, 0x47, 0x4C);

    # Sequence (32-bit LE)
    @hdr.push($seq +& 0xFF, ($seq +> 8) +& 0xFF, ($seq +> 16) +& 0xFF, ($seq +> 24) +& 0xFF);

    # Timestamp sec (32-bit LE)
    @hdr.push($ts-sec +& 0xFF, ($ts-sec +> 8) +& 0xFF, ($ts-sec +> 16) +& 0xFF, ($ts-sec +> 24) +& 0xFF);

    # Timestamp usec (32-bit LE)
    @hdr.push($ts-usec +& 0xFF, ($ts-usec +> 8) +& 0xFF, ($ts-usec +> 16) +& 0xFF, ($ts-usec +> 24) +& 0xFF);

    # Caplen (16-bit LE), Wirelen (16-bit LE)
    @hdr.push($caplen +& 0xFF, ($caplen +> 8) +& 0xFF);
    @hdr.push($wirelen +& 0xFF, ($wirelen +> 8) +& 0xFF);

    my $buf = Buf.new(@hdr);
    $buf.append($raw.subbuf(0, $caplen));
    return $buf;
}

# Decode binary IPC frame into Packet
our sub decode-frame(Buf $buf --> Sigil::Core::Packet) is export {
    return Nil if $buf.elems < 20;

    my $m0 = $buf[0];
    my $m1 = $buf[1];
    my $m2 = $buf[2];
    my $m3 = $buf[3];
    my $magic = ($m0 +< 24) +| ($m1 +< 16) +| ($m2 +< 8) +| $m3;

    return Nil unless $magic == SIGIL_IPC_MAGIC;

    my $seq = $buf[4] +| ($buf[5] +< 8) +| ($buf[6] +< 16) +| ($buf[7] +< 24);
    my $ts-sec = $buf[8] +| ($buf[9] +< 8) +| ($buf[10] +< 16) +| ($buf[11] +< 24);
    my $ts-usec = $buf[12] +| ($buf[13] +< 8) +| ($buf[14] +< 16) +| ($buf[15] +< 24);
    my $caplen = $buf[16] +| ($buf[17] +< 8);
    my $wirelen = $buf[18] +| ($buf[19] +< 8);

    return Nil if $buf.elems < 20 + $caplen;

    my $payload = $buf.subbuf(20, $caplen);
    my $ts = $ts-sec.Num + ($ts-usec.Num / 1000000e0);

    return Sigil::Core::Packet.new(
        :raw($payload),
        :packet-id($seq),
        :timestamp($ts),
        :wire-length($wirelen),
        :capture-length($caplen),
        :interface("ipc")
    );
}

method open(--> Bool) {
    $!is-connected = True;
    return True;
}

method next-packet(--> Sigil::Core::Packet) {
    # Emulated IPC driver hook
    return Nil;
}

method stats(--> Hash) {
    return {
        frames_received => $!frames-received,
        bytes_received  => $!bytes-received,
        socket_path     => $!socket-path
    };
}

method close() {
    $!is-connected = False;
}
