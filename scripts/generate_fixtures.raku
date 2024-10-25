#!/usr/bin/env raku
# scripts/generate_fixtures.raku - Generates binary golden PCAP test traces
#
# Synthesizes realistic wire-format PCAP captures containing standard multi-layer
# protocols, out-of-order TCP flows, DNS lookups, and security attack patterns.

use v6.d;
use lib 'lib';
use Sigil::Types;
use Sigil::Core::Checksum;
use Sigil::PCAP::Writer;
use Sigil::Core::Packet;

# Helper: Build Ethernet II frame
sub make-eth(Str $dst-mac, Str $src-mac, Int $ethertype, Buf $payload --> Buf) {
    my @b;
    # Destination MAC (6 bytes)
    for $dst-mac.split(":") -> $h { @b.push(:16($h)); }
    # Source MAC (6 bytes)
    for $src-mac.split(":") -> $h { @b.push(:16($h)); }
    # EtherType (2 bytes)
    @b.push(($ethertype +> 8) +& 0xFF, $ethertype +& 0xFF);
    @b.append($payload.list);
    return Buf.new(@b);
}

# Helper: Build IPv4 packet with valid header checksum
sub make-ipv4(Str $src-ip, Str $dst-ip, Int $proto, Buf $payload --> Buf) {
    my @hdr;
    my $ihl = 5;
    my $v_ihl = (4 +< 4) +| $ihl;
    my $total-len = 20 + $payload.elems;

    @hdr.push($v_ihl);
    @hdr.push(0); # DSCP/ECN
    @hdr.push(($total-len +> 8) +& 0xFF, $total-len +& 0xFF);
    @hdr.push(0x12, 0x34); # Identification
    @hdr.push(0x40, 0x00); # Flags (DF) + Fragment offset (0)
    @hdr.push(64); # TTL
    @hdr.push($proto);
    @hdr.push(0, 0); # Checksum placeholder

    for $src-ip.split(".") -> $octet { @hdr.push($octet.Int); }
    for $dst-ip.split(".") -> $octet { @hdr.push($octet.Int); }

    my $hdr-buf = Buf.new(@hdr);
    my $csum = Sigil::Core::Checksum::internet-checksum($hdr-buf);
    $hdr-buf[10] = ($csum +> 8) +& 0xFF;
    $hdr-buf[11] = $csum +& 0xFF;

    my @full;
    @full.append($hdr-buf.list);
    @full.append($payload.list);
    return Buf.new(@full);
}

# Helper: Build TCP segment with valid checksum
sub make-tcp(Str $src-ip, Str $dst-ip, Int $sport, Int $dport, Int $seq, Int $ack, Int $flags, Buf $payload = Buf.new --> Buf) {
    my @hdr;
    @hdr.push(($sport +> 8) +& 0xFF, $sport +& 0xFF);
    @hdr.push(($dport +> 8) +& 0xFF, $dport +& 0xFF);

    @hdr.push(($seq +> 24) +& 0xFF, ($seq +> 16) +& 0xFF, ($seq +> 8) +& 0xFF, $seq +& 0xFF);
    @hdr.push(($ack +> 24) +& 0xFF, ($ack +> 16) +& 0xFF, ($ack +> 8) +& 0xFF, $ack +& 0xFF);

    my $data-offset = 5; # 20 bytes header (no options)
    @hdr.push(($data-offset +< 4) +| 0);
    @hdr.push($flags);
    @hdr.push(0xFF, 0xFF); # Window size 65535
    @hdr.push(0, 0); # Checksum placeholder
    @hdr.push(0, 0); # Urgent pointer

    my @full;
    @full.append(@hdr);
    @full.append($payload.list);
    my $full-tcp = Buf.new(@full);

    my $csum = Sigil::Core::Checksum::tcp-checksum-ipv4($src-ip, $dst-ip, $full-tcp);
    $full-tcp[16] = ($csum +> 8) +& 0xFF;
    $full-tcp[17] = $csum +& 0xFF;

    return $full-tcp;
}

# Helper: Build UDP datagram
sub make-udp(Str $src-ip, Str $dst-ip, Int $sport, Int $dport, Buf $payload --> Buf) {
    my @hdr;
    my $udp-len = 8 + $payload.elems;
    @hdr.push(($sport +> 8) +& 0xFF, $sport +& 0xFF);
    @hdr.push(($dport +> 8) +& 0xFF, $dport +& 0xFF);
    @hdr.push(($udp-len +> 8) +& 0xFF, $udp-len +& 0xFF);
    @hdr.push(0, 0); # Checksum optional for IPv4

    my @full;
    @full.append(@hdr);
    @full.append($payload.list);
    return Buf.new(@full);
}

sub MAIN() {
    my $fix-dir = "t/fixtures";
    mkdir $fix-dir unless $fix-dir.IO.d;

    put "[Sigil] Generating binary golden PCAP test fixtures in $fix-dir...";

    # 1. Generate http_session.pcap
    {
        my $writer = Sigil::PCAP::Writer.new;
        my $cli-mac = "00:11:22:33:44:55";
        my $srv-mac = "00:aa:bb:cc:dd:ee";
        my $cli-ip = "192.168.1.100";
        my $srv-ip = "93.184.216.34"; # example.com
        my $sport = 49152;
        my $dport = 80;

        my $t = 1700000000.0e0;
        my $pkt-id = 1;

        # Packet 1: SYN
        my $syn-tcp = make-tcp($cli-ip, $srv-ip, $sport, $dport, 1000, 0, TCP_SYN);
        my $syn-ip = make-ipv4($cli-ip, $srv-ip, 6, $syn-tcp);
        my $syn-eth = make-eth($srv-mac, $cli-mac, 0x0800, $syn-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($syn-eth), :packet-id($pkt-id++), :timestamp($t)));

        # Packet 2: SYN-ACK
        $t += 0.015e0;
        my $sa-tcp = make-tcp($srv-ip, $cli-ip, $dport, $sport, 5000, 1001, TCP_SYN +| TCP_ACK);
        my $sa-ip = make-ipv4($srv-ip, $cli-ip, 6, $sa-tcp);
        my $sa-eth = make-eth($cli-mac, $srv-mac, 0x0800, $sa-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($sa-eth), :packet-id($pkt-id++), :timestamp($t)));

        # Packet 3: ACK
        $t += 0.001e0;
        my $ack-tcp = make-tcp($cli-ip, $srv-ip, $sport, $dport, 1001, 5001, TCP_ACK);
        my $ack-ip = make-ipv4($cli-ip, $srv-ip, 6, $ack-tcp);
        my $ack-eth = make-eth($srv-mac, $cli-mac, 0x0800, $ack-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($ack-eth), :packet-id($pkt-id++), :timestamp($t)));

        # Packet 4: HTTP GET Request
        $t += 0.002e0;
        my $http-req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Sigil/1.0\r\nAccept: */*\r\n\r\n".encode('ascii');
        my $req-tcp = make-tcp($cli-ip, $srv-ip, $sport, $dport, 1001, 5001, TCP_ACK +| TCP_PSH, Buf.new($http-req));
        my $req-ip = make-ipv4($cli-ip, $srv-ip, 6, $req-tcp);
        my $req-eth = make-eth($srv-mac, $cli-mac, 0x0800, $req-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($req-eth), :packet-id($pkt-id++), :timestamp($t)));

        # Packet 5: HTTP 200 OK Response
        $t += 0.020e0;
        my $http-resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!".encode('ascii');
        my $resp-tcp = make-tcp($srv-ip, $cli-ip, $dport, $sport, 5001, 1001 + $http-req.elems, TCP_ACK +| TCP_PSH, Buf.new($http-resp));
        my $resp-ip = make-ipv4($srv-ip, $cli-ip, 6, $resp-tcp);
        my $resp-eth = make-eth($cli-mac, $srv-mac, 0x0800, $resp-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($resp-eth), :packet-id($pkt-id++), :timestamp($t)));

        # Packet 6: FIN from Client
        $t += 0.005e0;
        my $fin-tcp = make-tcp($cli-ip, $srv-ip, $sport, $dport, 1001 + $http-req.elems, 5001 + $http-resp.elems, TCP_ACK +| TCP_FIN);
        my $fin-ip = make-ipv4($cli-ip, $srv-ip, 6, $fin-tcp);
        my $fin-eth = make-eth($srv-mac, $cli-mac, 0x0800, $fin-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($fin-eth), :packet-id($pkt-id++), :timestamp($t)));

        $writer.save-file("$fix-dir/http_session.pcap");
        put "  Created $fix-dir/http_session.pcap (6 packets, TCP handshake + HTTP request/response)";
    }

    # 2. Generate dns_query.pcap
    {
        my $writer = Sigil::PCAP::Writer.new;
        my $cli-mac = "00:11:22:33:44:55";
        my $dns-mac = "00:fe:dc:ba:98:76";
        my $cli-ip = "192.168.1.100";
        my $dns-ip = "8.8.8.8";
        my $sport = 53535;
        my $dport = 53;

        # DNS Query wire format for "example.com" type A class IN
        my @qbytes = (
            0x12, 0x34, # Transaction ID
            0x01, 0x00, # Flags: Standard query
            0x00, 0x01, # QDCOUNT = 1
            0x00, 0x00, # ANCOUNT = 0
            0x00, 0x00, # NSCOUNT = 0
            0x00, 0x00, # ARCOUNT = 0
            # QNAME: 7'example' 3'com' 0
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d,
            0x00,
            0x00, 0x01, # QTYPE: A (1)
            0x00, 0x01  # QCLASS: IN (1)
        );

        my $udp = make-udp($cli-ip, $dns-ip, $sport, $dport, Buf.new(@qbytes));
        my $ip = make-ipv4($cli-ip, $dns-ip, 17, $udp);
        my $eth = make-eth($dns-mac, $cli-mac, 0x0800, $ip);

        $writer.write-packet(Sigil::Core::Packet.new(:raw($eth), :packet-id(1), :timestamp(1700000100.0e0)));
        $writer.save-file("$fix-dir/dns_query.pcap");
        put "  Created $fix-dir/dns_query.pcap (1 packet, standard DNS query)";
    }

    # 3. Generate syn_flood.pcap
    {
        my $writer = Sigil::PCAP::Writer.new;
        my $target-ip = "10.0.0.1";
        my $target-mac = "00:00:5e:00:53:01";
        my $dport = 80;

        for 1..50 -> $i {
            my $src-ip = "172.16.0.$i";
            my $src-mac = sprintf("02:00:00:00:00:%02x", $i);
            my $sport = 10000 + $i;

            my $tcp = make-tcp($src-ip, $target-ip, $sport, $dport, $i * 100, 0, TCP_SYN);
            my $ip = make-ipv4($src-ip, $target-ip, 6, $tcp);
            my $eth = make-eth($target-mac, $src-mac, 0x0800, $ip);

            $writer.write-packet(Sigil::Core::Packet.new(
                :raw($eth),
                :packet-id($i),
                :timestamp(1700000200.0e0 + ($i * 0.001e0))
            ));
        }

        $writer.save-file("$fix-dir/syn_flood.pcap");
        put "  Created $fix-dir/syn_flood.pcap (50 packets, SYN flood anomaly pattern)";
    }

    # 4. Generate golden_multi_protocol.pcap
    {
        my $writer = Sigil::PCAP::Writer.new;
        my $cli-mac = "00:11:22:33:44:55";
        my $srv-mac = "00:aa:bb:cc:dd:ee";
        my $gw-mac  = "00:50:56:c0:00:01";
        my $cli-ip = "192.168.1.100";
        my $srv-ip = "93.184.216.34";
        my $dns-ip = "8.8.8.8";
        my $pkt-id = 1;
        my $t = 1700000000.0e0;

        # 4a. ARP Request
        my @arp-req = (
            0x00, 0x01, # Hardware type: Ethernet (1)
            0x08, 0x00, # Protocol type: IPv4 (0x0800)
            0x06,       # Hardware size: 6
            0x04,       # Protocol size: 4
            0x00, 0x01, # Opcode: Request (1)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # Sender MAC
            192, 168, 1, 100,                   # Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Target MAC
            192, 168, 1, 1                      # Target IP
        );
        my $arp-eth = make-eth("ff:ff:ff:ff:ff:ff", $cli-mac, 0x0806, Buf.new(@arp-req));
        $writer.write-packet(Sigil::Core::Packet.new(:raw($arp-eth), :packet-id($pkt-id++), :timestamp($t)));

        # 4b. DNS Query & Response
        $t += 0.005e0;
        my @dns-query = (
            0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01
        );
        my $dns-udp = make-udp($cli-ip, $dns-ip, 53535, 53, Buf.new(@dns-query));
        my $dns-ip-pkt = make-ipv4($cli-ip, $dns-ip, 17, $dns-udp);
        my $dns-eth = make-eth($gw-mac, $cli-mac, 0x0800, $dns-ip-pkt);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($dns-eth), :packet-id($pkt-id++), :timestamp($t)));

        # 4c. TCP Handshake + HTTP
        $t += 0.010e0;
        my $syn-tcp = make-tcp($cli-ip, $srv-ip, 49152, 80, 1000, 0, TCP_SYN);
        my $syn-ip = make-ipv4($cli-ip, $srv-ip, 6, $syn-tcp);
        my $syn-eth = make-eth($srv-mac, $cli-mac, 0x0800, $syn-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($syn-eth), :packet-id($pkt-id++), :timestamp($t)));

        $t += 0.012e0;
        my $sa-tcp = make-tcp($srv-ip, $cli-ip, 80, 49152, 5000, 1001, TCP_SYN +| TCP_ACK);
        my $sa-ip = make-ipv4($srv-ip, $cli-ip, 6, $sa-tcp);
        my $sa-eth = make-eth($cli-mac, $srv-mac, 0x0800, $sa-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($sa-eth), :packet-id($pkt-id++), :timestamp($t)));

        $t += 0.001e0;
        my $ack-tcp = make-tcp($cli-ip, $srv-ip, 49152, 80, 1001, 5001, TCP_ACK);
        my $ack-ip = make-ipv4($cli-ip, $srv-ip, 6, $ack-tcp);
        my $ack-eth = make-eth($srv-mac, $cli-mac, 0x0800, $ack-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($ack-eth), :packet-id($pkt-id++), :timestamp($t)));

        $t += 0.002e0;
        my $http-req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Sigil/1.0\r\n\r\n".encode('ascii');
        my $req-tcp = make-tcp($cli-ip, $srv-ip, 49152, 80, 1001, 5001, TCP_ACK +| TCP_PSH, Buf.new($http-req));
        my $req-ip = make-ipv4($cli-ip, $srv-ip, 6, $req-tcp);
        my $req-eth = make-eth($srv-mac, $cli-mac, 0x0800, $req-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($req-eth), :packet-id($pkt-id++), :timestamp($t)));

        $t += 0.015e0;
        my $http-resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello Sigil!".encode('ascii');
        my $resp-tcp = make-tcp($srv-ip, $cli-ip, 80, 49152, 5001, 1001 + $http-req.elems, TCP_ACK +| TCP_PSH, Buf.new($http-resp));
        my $resp-ip = make-ipv4($srv-ip, $cli-ip, 6, $resp-tcp);
        my $resp-eth = make-eth($cli-mac, $srv-mac, 0x0800, $resp-ip);
        $writer.write-packet(Sigil::Core::Packet.new(:raw($resp-eth), :packet-id($pkt-id++), :timestamp($t)));

        $writer.save-file("$fix-dir/golden_multi_protocol.pcap");
        put "  Created $fix-dir/golden_multi_protocol.pcap ($pkt-id packets, multi-protocol suite)";
    }

    put "[Sigil] Golden test fixtures generated successfully.";
}
