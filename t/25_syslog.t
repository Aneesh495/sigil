# Test suite for Sigil::Grammar::Protocol::Syslog
use Test;
use Sigil::Grammar::Protocol::Syslog;
use Sigil::Types;

plan 11;

# RFC 5424 IETF Syslog: PRI = 165 -> Facility 20 (local4), Severity 5 (Notice)
my $rfc5424_str = "<165>1 2026-10-27T10:00:00.000Z edge-gw-01 sigild 4096 MSG01 - Telemetry buffer flushed.";
my $rfc5424_raw = Buf.new($rfc5424_str.encode('utf-8'));

my $layer_5424 = Sigil::Grammar::Protocol::Syslog.dissect($rfc5424_raw);
is $layer_5424.name, "Syslog", "Layer identified as Syslog";
is $layer_5424.status, STATUS_OK, "Status is OK";
is $layer_5424.val("syslog.pri"), 165, "PRI parsed as 165";
is $layer_5424.val("syslog.facility"), 20, "Facility parsed as 20 (local4)";
is $layer_5424.val("syslog.severity"), 5, "Severity parsed as 5 (Notice)";
is $layer_5424.val("syslog.version"), 1, "Syslog version is 1";
is $layer_5424.val("syslog.hostname"), "edge-gw-01", "Hostname parsed";
is $layer_5424.val("syslog.app_name"), "sigild", "App name parsed as 'sigild'";
ok $layer_5424.display-name.contains("RFC 5424"), "Display name indicates RFC 5424 format";

# RFC 3164 Legacy Syslog: PRI = 34 -> Facility 4 (auth), Severity 2 (Critical)
my $rfc3164_str = "<34>Oct 27 10:00:00 host su: auth failure";
my $rfc3164_raw = Buf.new($rfc3164_str.encode('utf-8'));
my $layer_3164 = Sigil::Grammar::Protocol::Syslog.dissect($rfc3164_raw);
is $layer_3164.val("syslog.facility"), 4, "RFC 3164 Facility parsed as 4 (auth)";

# Truncated Syslog (< 4 bytes)
my $trunc_raw = Buf.new("<1>".encode('ascii'));
my $layer_trunc = Sigil::Grammar::Protocol::Syslog.dissect($trunc_raw);
is $layer_trunc.status, STATUS_TRUNCATED, "Truncated Syslog yields STATUS_TRUNCATED";
