# Test suite for Sigil::Grammar::Protocol::TLS
use Test;
use Sigil::Grammar::Protocol::TLS;
use Sigil::Types;

plan 11;

# Construct synthetic TLS ClientHello with SNI = "github.com":
# Record Layer: ContentType 22 (Handshake), Version 0x0301 (TLS 1.0 legacy), Len = 4 + 43
# Handshake: Type 1 (ClientHello), Length 43
# Client Version: 0x0303 (TLS 1.2)
# Random: 32 bytes
# Session ID: len 0
# Cipher Suites: len 2 (0x1301)
# Compression: len 1 (0x00)
# Extensions: len 15
#   Ext 0 (SNI): len 11
#     List len: 9, Type 0 (host_name), Name len: 6 ("github") -> let's do "github.com" (len 10)
my @client_hello = (
    # TLS Record Header
    0x16,                               # ContentType = 22 (Handshake)
    0x03, 0x01,                         # Version = TLS 1.0 (0x0301)
    0x00, 0x48,                         # Record Length = 72 bytes
    # Handshake Header
    0x01,                               # Handshake Type = 1 (ClientHello)
    0x00, 0x00, 0x44,                   # Handshake Length = 68 bytes
    # Client Version
    0x03, 0x03,                         # TLS 1.2
    # Random (32 bytes)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    # Session ID Length = 0
    0x00,
    # Cipher Suites: len 2 (TLS_AES_128_GCM_SHA256 = 0x1301)
    0x00, 0x02, 0x13, 0x01,
    # Compression: len 1, 0x00 (None)
    0x01, 0x00,
    # Extensions: total length = 19 bytes
    0x00, 0x13,
    # Extension 0 (SNI): ext_type = 0x0000, ext_len = 15 bytes
    0x00, 0x00, 0x00, 0x0f,
    # ServerNameList len = 13
    0x00, 0x0d,
    # NameType = 0 (host_name), NameLen = 10 ("github.com")
    0x00, 0x00, 0x0a,
    # "github.com" in ASCII
    0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d
);

my $tls_raw = Buf.new(@client_hello);

my $layer = Sigil::Grammar::Protocol::TLS.dissect($tls_raw);
is $layer.name, "TLS", "Layer identified as TLS";
is $layer.status, STATUS_OK, "Status is OK";
is $layer.val("tls.record.content_type"), 22, "Content type is 22 (Handshake)";
is $layer.val("tls.record.version"), 0x0301, "Legacy version is 0x0301 (TLS 1.0)";
is $layer.val("tls.handshake.type"), 1, "Handshake type is 1 (ClientHello)";
is $layer.val("tls.handshake.client_version"), 0x0303, "Client version is TLS 1.2";
is $layer.val("tls.handshake.sni"), "github.com", "Server Name Indication (SNI) extracted as 'github.com'";
ok $layer.display-name.contains("ClientHello"), "Display name contains ClientHello";
ok $layer.display-name.contains("SNI=github.com"), "Display name contains SNI tag";

# TLS Application Data record (ContentType 23)
my $app_data_raw = Buf.new(0x17, 0x03, 0x03, 0x00, 0x10, 1..16);
my $l_app = Sigil::Grammar::Protocol::TLS.dissect($app_data_raw);
is $l_app.val("tls.record.content_type"), 23, "Content type is 23 (ApplicationData)";

# Truncated TLS record (< 5 bytes)
my $trunc_raw = Buf.new(0x16, 0x03, 0x03);
my $l_trunc = Sigil::Grammar::Protocol::TLS.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated TLS record yields STATUS_TRUNCATED";
