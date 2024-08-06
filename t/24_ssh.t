# Test suite for Sigil::Grammar::Protocol::SSH
use Test;
use Sigil::Grammar::Protocol::SSH;
use Sigil::Types;

plan 10;

# SSH-2.0 Identification Banner
my $banner_str = "SSH-2.0-OpenSSH_9.6p1 Debian-1\r\n";
my $banner_raw = Buf.new($banner_str.encode('ascii'));

my $layer_banner = Sigil::Grammar::Protocol::SSH.dissect($banner_raw);
is $layer_banner.name, "SSH", "Layer identified as SSH";
is $layer_banner.status, STATUS_OK, "Status is OK";
is $layer_banner.val("ssh.banner"), "SSH-2.0-OpenSSH_9.6p1 Debian-1", "Banner parsed without trailing CRLF";
is $layer_banner.val("ssh.proto_version"), "2.0", "Protocol version parsed as 2.0";
is $layer_banner.val("ssh.software_version"), "OpenSSH_9.6p1", "Software version parsed";
ok $layer_banner.display-name.contains("SSH Identification"), "Display name contains banner tag";

# SSH Binary Packet: SSH_MSG_KEXINIT (Message Code 20, Packet Length 16, Padding 6)
# Packet length: 16 (4 bytes)
# Padding length: 6 (1 byte)
# Message code: 20 (1 byte)
# Payload: 9 bytes
# Padding: 6 bytes
my @kex_bytes = (
    0x00, 0x00, 0x00, 0x10,             # Packet length = 16
    0x06,                               # Padding length = 6
    0x14                                # Message code = 20 (SSH_MSG_KEXINIT)
);
for 1..15 { @kex_bytes.push(0); }
my $ssh_kex = Buf.new(@kex_bytes);

my $layer_kex = Sigil::Grammar::Protocol::SSH.dissect($ssh_kex);
is $layer_kex.val("ssh.packet_length"), 16, "Packet length is 16";
is $layer_kex.val("ssh.message_code"), 20, "Message code is 20 (SSH_MSG_KEXINIT)";
ok $layer_kex.display-name.contains("SSH_MSG_KEXINIT"), "Display name contains message name";

# Truncated SSH packet (< 4 bytes)
my $trunc_raw = Buf.new(0x53, 0x53);
my $l_trunc = Sigil::Grammar::Protocol::SSH.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated SSH yields STATUS_TRUNCATED";
