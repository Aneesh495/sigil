use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Capture::IPC;
use Sigil::Capture::Offline;
use Sigil::PCAP::Writer;

plan 11;

# 1. IPC binary frame encoding and decoding
{
    my $raw = Buf.new("SIGIL_IPC_BINARY_DATA".encode('ascii'));
    my $pkt = Sigil::Core::Packet.new(
        :raw($raw),
        :packet-id(999),
        :timestamp(1700000000.750000e0),
        :wire-length($raw.elems),
        :capture-length($raw.elems)
    );

    my $frame = Sigil::Capture::IPC::encode-frame($pkt);
    ok $frame.elems >= 20 + $raw.elems, "IPC frame length includes 20-byte header";

    # Magic check
    is $frame[0], 0x53, "Magic byte 0 is 'S'";
    is $frame[1], 0x49, "Magic byte 1 is 'I'";
    is $frame[2], 0x47, "Magic byte 2 is 'G'";
    is $frame[3], 0x4C, "Magic byte 3 is 'L'";

    # Decode frame
    my $decoded = Sigil::Capture::IPC::decode-frame($frame);
    ok $decoded.defined, "IPC frame decoded successfully";
    is $decoded.packet-id, 999, "Decoded packet ID matches original (999)";
    is-approx $decoded.timestamp, 1700000000.750000e0, 1e-4, "Decoded timestamp matches original";
    is $decoded.raw.decode('ascii'), "SIGIL_IPC_BINARY_DATA", "Decoded payload matches original data";
}

# 2. Offline replay driver
{
    my $writer = Sigil::PCAP::Writer.new;
    my $tmp-pcap = "/tmp/sigil_test_capture_{$*PID}.pcap";

    my $raw = Buf.new("REPLAY_TEST".encode('ascii'));
    my $pkt = Sigil::Core::Packet.new(
        :raw($raw),
        :packet-id(1),
        :timestamp(1700000000.0e0),
        :wire-length($raw.elems),
        :capture-length($raw.elems)
    );
    $writer.write-packet($pkt);
    $writer.save-file($tmp-pcap);

    my $driver = Sigil::Capture::Offline.new(:filepath($tmp-pcap));
    ok $driver.open(), "Offline driver opened PCAP trace file";

    my $replayed = $driver.next-packet();
    is $replayed.raw.decode('ascii'), "REPLAY_TEST", "Offline driver yielded correct packet payload";

    $driver.close();
    unlink $tmp-pcap if $tmp-pcap.IO.e;
}

done-testing;
