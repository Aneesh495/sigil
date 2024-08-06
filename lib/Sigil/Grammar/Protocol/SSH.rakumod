# Sigil::Grammar::Protocol::SSH - Secure Shell protocol dissector (RFC 4253)
#
# Parses SSH identification banner exchanges (SSH-2.0-Software), Binary Packet Protocol
# framing, SSH message numbers (KEXINIT, NEWKEYS, DISCONNECT), and encrypted payload markers.

unit class Sigil::Grammar::Protocol::SSH;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing SSH stream data
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 4 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("SSH"),
            :display-name("SSH (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("SSH packet truncated: expected at least 4 bytes")
        );
    }

    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start-offset = $buf.offset;

    # Check for Identification string banner (starts with "SSH-")
    my $b0 = $buf.peek-uint8(0);
    my $b1 = $buf.peek-uint8(1);
    my $b2 = $buf.peek-uint8(2);
    my $b3 = $buf.peek-uint8(3);

    my $is-banner = ($b0 == 0x53 && $b1 == 0x53 && $b2 == 0x48 && $b3 == 0x2D); # "SSH-"

    my $fl = Sigil::Core::FieldList.new;
    my $disp = "SSH";
    my $header-len = 0;

    if $is-banner {
        # Protocol Version Exchange (RFC 4253 Section 4.2)
        my @chars;
        while $buf.remaining > 0 {
            my $ch = $buf.read-uint8();
            if $ch == 0x0A { # LF ends banner line
                last;
            }
            @chars.push($ch.chr) if $ch != 0x0D; # Strip CR
        }
        my $banner = @chars.join('');
        $fl.add(Sigil::Core::StringField.new(:name("Identification Banner"), :key("ssh.banner"), :value($banner)));

        if $banner ~~ /^ 'SSH-' (<[0..9.]>+) '-' (\S+) / {
            $fl.add(Sigil::Core::StringField.new(:name("Protocol Version"), :key("ssh.proto_version"), :value(~$0)));
            $fl.add(Sigil::Core::StringField.new(:name("Software Version"), :key("ssh.software_version"), :value(~$1)));
        }

        $header-len = $buf.offset - $start-offset;
        $disp = sprintf("SSH Identification (%s)", $banner.substr(0, 32));
    } else {
        # Binary Packet Protocol (RFC 4253 Section 6)
        my $pkt-len = $buf.read-uint32-be();
        my $pad-len = $buf.read-uint8();

        my $msg-code = -1;
        if $buf.remaining >= 1 {
            $msg-code = $buf.read-uint8();
        }

        my %msg-names = (
            1  => "SSH_MSG_DISCONNECT",
            2  => "SSH_MSG_IGNORE",
            3  => "SSH_MSG_UNIMPLEMENTED",
            4  => "SSH_MSG_DEBUG",
            5  => "SSH_MSG_SERVICE_REQUEST",
            6  => "SSH_MSG_SERVICE_ACCEPT",
            20 => "SSH_MSG_KEXINIT",
            21 => "SSH_MSG_NEWKEYS",
            30 => "SSH_MSG_KEXDH_INIT",
            31 => "SSH_MSG_KEXDH_REPLY",
            50 => "SSH_MSG_USERAUTH_REQUEST",
            51 => "SSH_MSG_USERAUTH_FAILURE",
            52 => "SSH_MSG_USERAUTH_SUCCESS",
            80 => "SSH_MSG_GLOBAL_REQUEST",
            90 => "SSH_MSG_CHANNEL_OPEN",
            91 => "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
            92 => "SSH_MSG_CHANNEL_OPEN_FAILURE",
            93 => "SSH_MSG_CHANNEL_WINDOW_ADJUST",
            94 => "SSH_MSG_CHANNEL_DATA",
            95 => "SSH_MSG_CHANNEL_EXTENDED_DATA",
            96 => "SSH_MSG_CHANNEL_EOF",
            97 => "SSH_MSG_CHANNEL_CLOSE"
        );

        $fl.add(Sigil::Core::IntField.new(:name("Packet Length"), :key("ssh.packet_length"), :offset-bytes(0), :length-bytes(4), :value($pkt-len)));
        $fl.add(Sigil::Core::IntField.new(:name("Padding Length"), :key("ssh.padding_length"), :offset-bytes(4), :length-bytes(1), :value($pad-len)));

        if $msg-code >= 0 {
            $fl.add(Sigil::Core::EnumField.new(
                :name("Message Code"),
                :key("ssh.message_code"),
                :offset-bytes(5),
                :length-bytes(1),
                :value($msg-code),
                :name-map(%msg-names)
            ));
            my $msg-desc = %msg-names{$msg-code} // sprintf("Message %d", $msg-code);
            $disp = sprintf("SSH2 %s (PacketLen=%d)", $msg-desc, $pkt-len);
        } else {
            $disp = sprintf("SSH2 Encrypted Packet (Len=%d)", $pkt-len);
        }

        $header-len = min(4 + $pkt-len, $raw.elems - $start-offset);
    }

    my $raw-header = $raw.subbuf($start-offset, $header-len);

    return Sigil::Core::Layer.new(
        :name("SSH"),
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
