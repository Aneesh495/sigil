use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::PCAP::Header;
use Sigil::PCAP::Reader;
use Sigil::PCAP::Writer;

plan 14;

# 1. PCAP Writer: write packets to in-memory buffer
{
    my $writer = Sigil::PCAP::Writer.new(:is-little-endian(True), :is-nanosecond(False));

    my $raw1 = Buf.new("PACKET_ONE_PAYLOAD_DATA".encode('ascii'));
    my $pkt1 = Sigil::Core::Packet.new(
        :raw($raw1),
        :packet-id(1),
        :timestamp(1700000000.500000e0),
        :wire-length($raw1.elems),
        :capture-length($raw1.elems)
    );
    $writer.write-packet($pkt1);

    my $raw2 = Buf.new("PACKET_TWO_PAYLOAD_MORE".encode('ascii'));
    my $pkt2 = Sigil::Core::Packet.new(
        :raw($raw2),
        :packet-id(2),
        :timestamp(1700000001.250000e0),
        :wire-length($raw2.elems),
        :capture-length($raw2.elems)
    );
    $writer.write-packet($pkt2);

    is $writer.packet-count, 2, "Writer recorded 2 packets";
    my $bytes = $writer.to-bytes();
    ok $bytes.elems > 24 + 16 + 16, "Serialized buffer contains header and both packet records";

    # 2. Read back using PCAP Reader
    my $reader = Sigil::PCAP::Reader.from-buffer($bytes);
    ok $reader.is-little-endian, "Reader correctly identifies little-endian magic";
    nok $reader.is-nanosecond, "Reader correctly identifies microsecond timestamp mode";

    my $read1 = $reader.read-next();
    ok $read1.defined, "Packet 1 read successfully";
    is $read1.packet-id, 1, "Packet 1 ID matches";
    is $read1.capture-length, $raw1.elems, "Packet 1 capture length matches";
    is-approx $read1.timestamp, 1700000000.500000e0, 1e-4, "Packet 1 timestamp matches";
    is $read1.raw.decode('ascii'), "PACKET_ONE_PAYLOAD_DATA", "Packet 1 payload data matches";

    my $read2 = $reader.read-next();
    ok $read2.defined, "Packet 2 read successfully";
    is $read2.packet-id, 2, "Packet 2 ID matches";
    is-approx $read2.timestamp, 1700000001.250000e0, 1e-4, "Packet 2 timestamp matches";
    is $read2.raw.decode('ascii'), "PACKET_TWO_PAYLOAD_MORE", "Packet 2 payload data matches";

    my $eof = $reader.read-next();
    nok $eof.defined, "End of file reached, returning Nil";
}

done-testing;
