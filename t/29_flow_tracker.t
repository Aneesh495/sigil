use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Packet;
use Sigil::Core::Layer;
use Sigil::Core::Field;
use Sigil::Flow::Key;
use Sigil::Flow::TCPState;
use Sigil::Flow::Session;
use Sigil::Flow::Tracker;

plan 17;

# Helper to construct mock IP/TCP packet
sub make-tcp-packet(Str $src, Str $dst, Int $sport, Int $dport, Int $flags, Int $seq, Buf $payload = Buf.new --> Sigil::Core::Packet) {
    my $pkt = Sigil::Core::Packet.new(:raw(Buf.new(0 xx 64)));

    my $ip-fields = Sigil::Core::FieldList.new;
    $ip-fields.add(Sigil::Core::AddressField.new(:name("Source IP"), :key("ip.src"), :value($src), :address-type("ipv4")));
    $ip-fields.add(Sigil::Core::AddressField.new(:name("Destination IP"), :key("ip.dst"), :value($dst), :address-type("ipv4")));
    $ip-fields.add(Sigil::Core::IntField.new(:name("Protocol"), :key("ip.proto"), :value(6)));
    my $ip-layer = Sigil::Core::Layer.new(:name("IPv4"), :fields($ip-fields));
    $pkt.push-layer($ip-layer);

    my $tcp-fields = Sigil::Core::FieldList.new;
    $tcp-fields.add(Sigil::Core::IntField.new(:name("Source Port"), :key("tcp.srcport"), :value($sport)));
    $tcp-fields.add(Sigil::Core::IntField.new(:name("Destination Port"), :key("tcp.dstport"), :value($dport)));
    $tcp-fields.add(Sigil::Core::IntField.new(:name("Sequence Number"), :key("tcp.seq"), :value($seq)));
    $tcp-fields.add(Sigil::Core::IntField.new(:name("Flags"), :key("tcp.flags"), :value($flags)));
    my $tcp-layer = Sigil::Core::Layer.new(:name("TCP"), :fields($tcp-fields), :raw-payload($payload));
    $pkt.push-layer($tcp-layer);

    return $pkt;
}

# 1. Flow Key tests
{
    my $pkt1 = make-tcp-packet("192.168.1.10", "10.0.0.1", 54321, 80, TCP_SYN, 100);
    my $key1 = Sigil::Flow::Key.from-packet($pkt1);
    is $key1.proto, "TCP", "Key protocol is TCP";
    is $key1.src-ip, "192.168.1.10", "Key src-ip matches";
    is $key1.src-port, 54321, "Key src-port matches";
    ok $key1.is-forward("192.168.1.10", 54321), "Packet from src is forward direction";
    nok $key1.is-forward("10.0.0.1", 80), "Packet from dst is reverse direction";

    # Reverse key produces same canonical-id
    my $rev-key = $key1.reverse;
    is $rev-key.canonical-id, $key1.canonical-id, "Canonical ID is invariant under direction reversal";
}

# 2. TCP State Machine transitions
{
    my $state = Sigil::Flow::TCPState.new;
    is $state.summary, "C:LISTEN/S:LISTEN", "Initial state is LISTEN";

    # SYN from client
    $state.process-flags(TCP_SYN, True);
    is $state.client-state, TCP_STATE_SYN_SENT, "Client moves to SYN_SENT on SYN";

    # SYN-ACK from server
    $state.process-flags(TCP_SYN +| TCP_ACK, False);
    is $state.server-state, TCP_STATE_SYN_RECEIVED, "Server moves to SYN_RECEIVED on SYN-ACK";

    # Final ACK from client completes 3-way handshake
    $state.process-flags(TCP_ACK, True);
    ok $state.is-established, "Handshake complete: state is ESTABLISHED";
    is $state.summary, "ESTABLISHED", "Summary reports ESTABLISHED";

    # RST aborts connection
    $state.process-flags(TCP_RST, False);
    ok $state.is-reset, "RST marks connection as reset";
    ok $state.is-closed, "Reset connection is also closed";
    is $state.summary, "RESET", "Summary reports RESET";
}

# 3. Flow Tracker integration and reassembly
{
    my $tracker = Sigil::Flow::Tracker.new;
    my $reassembled-data = "";

    $tracker.on-payload-reassembled = sub ($sess, $is-c2s, $payload) {
        $reassembled-data ~= $payload.decode('ascii');
    };

    # Handshake packets
    my $syn = make-tcp-packet("10.1.1.2", "10.1.1.1", 45000, 80, TCP_SYN, 500);
    $tracker.process($syn, 100.0e0);

    my $syn-ack = make-tcp-packet("10.1.1.1", "10.1.1.2", 80, 45000, TCP_SYN +| TCP_ACK, 900);
    $tracker.process($syn-ack, 100.02e0);

    my $ack = make-tcp-packet("10.1.1.2", "10.1.1.1", 45000, 80, TCP_ACK, 501);
    my $session = $tracker.process($ack, 100.03e0);

    is $tracker.active-count, 1, "One active session tracked";
    ok $session.handshake-rtt > 0.019e0, "Handshake RTT computed correctly";

    # Data transfer
    my $payload = Buf.new("SIGIL_FLOW_OK".encode('ascii'));
    my $data-pkt = make-tcp-packet("10.1.1.2", "10.1.1.1", 45000, 80, TCP_ACK +| TCP_PSH, 501, $payload);
    $tracker.process($data-pkt, 100.05e0);

    is $reassembled-data, "SIGIL_FLOW_OK", "Payload callback received reassembled contiguous stream data";
}

done-testing;
