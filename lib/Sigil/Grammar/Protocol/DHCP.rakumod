# Sigil::Grammar::Protocol::DHCP - Dynamic Host Configuration Protocol dissector (RFC 2131)
#
# Parses BOOTP legacy base headers, DHCP transaction parameters, magic cookie verification,
# and variable-length DHCP options (Discover, Offer, Request, Ack, Router, DNS, Lease Time).

unit class Sigil::Grammar::Protocol::DHCP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing DHCP datagram
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));

    # Base BOOTP/DHCP header requires at least 240 bytes (up to magic cookie)
    if $buf.remaining < 240 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("DHCP"),
            :display-name("DHCP (Truncated)"),
            :offset($offset),
            :header-length($buf.remaining),
            :payload-length(0),
            :raw-header($buf.read-remaining),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("DHCP packet truncated: expected at least 240 bytes for BOOTP base")
        );
    }

    my $start-offset = $buf.offset;
    my $op = $buf.read-uint8();
    my $htype = $buf.read-uint8();
    my $hlen = $buf.read-uint8();
    my $hops = $buf.read-uint8();

    my $xid = $buf.read-uint32-be();
    my $secs = $buf.read-uint16-be();
    my $flags = $buf.read-uint16-be();
    my $is-broadcast = ($flags +& 0x8000) != 0;

    my $ciaddr = $buf.read-ipv4();
    my $yiaddr = $buf.read-ipv4();
    my $siaddr = $buf.read-ipv4();
    my $giaddr = $buf.read-ipv4();

    my $chaddr-raw = $buf.read-bytes(16);
    my $chaddr-mac = $chaddr-raw.subbuf(0, 6).list.map({ sprintf("%02x", $_) }).join(':');

    my $sname = $buf.read-cstring(64);
    $buf.seek($start-offset + 44 + 64); # Align to file field

    my $file = $buf.read-cstring(128);
    $buf.seek($start-offset + 44 + 64 + 128); # Align to magic cookie

    my $magic-cookie = $buf.read-uint32-be();
    my $valid-cookie = ($magic-cookie == 0x63825363);

    my %op-names = (
        1 => "BootRequest",
        2 => "BootReply"
    );

    my %msg-types = (
        1 => "DHCPDISCOVER",
        2 => "DHCPOFFER",
        3 => "DHCPREQUEST",
        4 => "DHCPDECLINE",
        5 => "DHCPACK",
        6 => "DHCPNAK",
        7 => "DHCPRELEASE",
        8 => "DHCPINFORM"
    );

    my $fl = Sigil::Core::FieldList.new;
    $fl.add(Sigil::Core::EnumField.new(:name("Message Opcode"), :key("dhcp.op"), :offset-bytes(0), :length-bytes(1), :value($op), :name-map(%op-names)));
    $fl.add(Sigil::Core::IntField.new(:name("Hardware Type"), :key("dhcp.htype"), :offset-bytes(1), :length-bytes(1), :value($htype)));
    $fl.add(Sigil::Core::IntField.new(:name("Hardware Address Length"), :key("dhcp.hlen"), :offset-bytes(2), :length-bytes(1), :value($hlen)));
    $fl.add(Sigil::Core::IntField.new(:name("Hops"), :key("dhcp.hops"), :offset-bytes(3), :length-bytes(1), :value($hops)));
    $fl.add(Sigil::Core::IntField.new(:name("Transaction ID"), :key("dhcp.xid"), :offset-bytes(4), :length-bytes(4), :value($xid), :radix("hex"), :bit-width(32)));
    $fl.add(Sigil::Core::IntField.new(:name("Seconds Elapsed"), :key("dhcp.secs"), :offset-bytes(8), :length-bytes(2), :value($secs)));
    $fl.add(Sigil::Core::FlagField.new(:name("Broadcast Flag"), :key("dhcp.flags.broadcast"), :offset-bytes(10), :length-bytes(2), :mask(0x8000), :is-set($is-broadcast)));

    $fl.add(Sigil::Core::AddressField.new(:name("Client IP (ciaddr)"), :key("dhcp.ciaddr"), :offset-bytes(12), :length-bytes(4), :value($ciaddr), :address-type("ipv4")));
    $fl.add(Sigil::Core::AddressField.new(:name("Your IP (yiaddr)"), :key("dhcp.yiaddr"), :offset-bytes(16), :length-bytes(4), :value($yiaddr), :address-type("ipv4")));
    $fl.add(Sigil::Core::AddressField.new(:name("Next Server IP (siaddr)"), :key("dhcp.siaddr"), :offset-bytes(20), :length-bytes(4), :value($siaddr), :address-type("ipv4")));
    $fl.add(Sigil::Core::AddressField.new(:name("Relay Agent IP (giaddr)"), :key("dhcp.giaddr"), :offset-bytes(24), :length-bytes(4), :value($giaddr), :address-type("ipv4")));
    $fl.add(Sigil::Core::AddressField.new(:name("Client MAC (chaddr)"), :key("dhcp.chaddr"), :offset-bytes(28), :length-bytes(16), :value($chaddr-mac), :address-type("mac")));

    $fl.add(Sigil::Core::IntField.new(:name("Magic Cookie"), :key("dhcp.magic"), :offset-bytes(236), :length-bytes(4), :value($magic-cookie), :radix("hex"), :bit-width(32)));

    my $dhcp-msg-type = 0;

    # Parse DHCP Options if valid magic cookie present
    if $valid-cookie {
        while $buf.remaining > 0 {
            my $opt-code = $buf.read-uint8();
            last if $opt-code == 255; # End option
            next if $opt-code == 0;   # Pad option

            last if $buf.remaining < 1;
            my $opt-len = $buf.read-uint8();
            last if $buf.remaining < $opt-len;

            my $opt-bytes = $buf.read-bytes($opt-len);

            if $opt-code == 53 && $opt-len == 1 { # DHCP Message Type
                $dhcp-msg-type = $opt-bytes[0];
                $fl.add(Sigil::Core::EnumField.new(
                    :name("DHCP Message Type"),
                    :key("dhcp.option.type"),
                    :value($dhcp-msg-type),
                    :name-map(%msg-types)
                ));
            } elsif $opt-code == 54 && $opt-len == 4 { # Server Identifier
                my $srv-ip = $opt-bytes.list.join('.');
                $fl.add(Sigil::Core::AddressField.new(
                    :name("Server Identifier"),
                    :key("dhcp.option.server_id"),
                    :value($srv-ip),
                    :address-type("ipv4")
                ));
            } elsif $opt-code == 51 && $opt-len == 4 { # IP Address Lease Time
                my $lease = ($opt-bytes[0] +< 24) +| ($opt-bytes[1] +< 16) +| ($opt-bytes[2] +< 8) +| $opt-bytes[3];
                $fl.add(Sigil::Core::IntField.new(
                    :name("IP Address Lease Time"),
                    :key("dhcp.option.lease_time"),
                    :value($lease)
                ));
            } elsif $opt-code == 1 && $opt-len == 4 { # Subnet Mask
                my $mask = $opt-bytes.list.join('.');
                $fl.add(Sigil::Core::AddressField.new(
                    :name("Subnet Mask"),
                    :key("dhcp.option.subnet_mask"),
                    :value($mask),
                    :address-type("ipv4")
                ));
            } elsif $opt-code == 3 && $opt-len >= 4 { # Router
                my $router = $opt-bytes.subbuf(0, 4).list.join('.');
                $fl.add(Sigil::Core::AddressField.new(
                    :name("Router (Gateway)"),
                    :key("dhcp.option.router"),
                    :value($router),
                    :address-type("ipv4")
                ));
            } elsif $opt-code == 6 && $opt-len >= 4 { # Domain Name Server
                my $dns = $opt-bytes.subbuf(0, 4).list.join('.');
                $fl.add(Sigil::Core::AddressField.new(
                    :name("Domain Name Server"),
                    :key("dhcp.option.dns"),
                    :value($dns),
                    :address-type("ipv4")
                ));
            } elsif $opt-code == 12 { # Host Name
                my $hname = $opt-bytes.decode('ascii');
                $fl.add(Sigil::Core::StringField.new(
                    :name("Host Name"),
                    :key("dhcp.option.hostname"),
                    :value($hname)
                ));
            }
        }
    }

    my $header-len = $buf.offset - $start-offset;
    my $raw-header = $raw.subbuf($start-offset, $header-len);

    my $title = %msg-types{$dhcp-msg-type} // (%op-names{$op} // "DHCP");
    my $disp = sprintf("DHCP (%s, xid=0x%08x)", $title, $xid);

    return Sigil::Core::Layer.new(
        :name("DHCP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw-header),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
