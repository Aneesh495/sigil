# Sigil::Grammar::Protocol::Syslog - System Logging Protocol dissector (RFC 3164 / RFC 5424)
#
# Parses BSD Syslog (RFC 3164) and IETF Syslog (RFC 5424) frames, PRI decoding
# (Facility and Severity levels), ISO 8601 timestamps, App-Names, and Structured Data blocks.

unit class Sigil::Grammar::Protocol::Syslog;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

# Dissect raw byte buffer containing Syslog message
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 4 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("Syslog"),
            :display-name("Syslog (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED),
            :status-detail("Syslog message truncated: expected at least 4 bytes")
        );
    }

    my $slice = $raw.subbuf($offset);
    my $text = "";
    try {
        $text = $slice.decode('utf-8');
    }
    if $text eq "" {
        try { $text = $slice.decode('latin-1'); }
    }

    my %facilities = (
        0  => "kernel",
        1  => "user-level",
        2  => "mail",
        3  => "system daemons",
        4  => "security/authorization",
        5  => "internal syslogd",
        6  => "line printer",
        7  => "network news",
        8  => "UUCP",
        9  => "clock daemon",
        10 => "security/authorization",
        11 => "FTP daemon",
        12 => "NTP subsystem",
        13 => "log audit",
        14 => "log alert",
        15 => "clock daemon",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7"
    );

    my %severities = (
        0 => "Emergency",
        1 => "Alert",
        2 => "Critical",
        3 => "Error",
        4 => "Warning",
        5 => "Notice",
        6 => "Informational",
        7 => "Debug"
    );

    my $fl = Sigil::Core::FieldList.new;
    my $disp = "Syslog";
    my $status = STATUS_OK;

    # Parse PRI (<digits>)
    if $text ~~ /^ '<' (\d**1..3) '>' (.*) $/ {
        my $pri = $0.Int;
        my $body = ~$1;

        my $facility = $pri +> 3;
        my $severity = $pri +& 0x07;

        $fl.add(Sigil::Core::IntField.new(:name("Priority (PRI)"), :key("syslog.pri"), :value($pri)));
        $fl.add(Sigil::Core::EnumField.new(:name("Facility"), :key("syslog.facility"), :value($facility), :name-map(%facilities)));
        $fl.add(Sigil::Core::EnumField.new(:name("Severity"), :key("syslog.severity"), :value($severity), :name-map(%severities)));

        # Check for RFC 5424 header: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD] SP MSG
        if $body ~~ /^ (\d+) \s+ (\S+) \s+ (\S+) \s+ (\S+) \s+ (\S+) \s+ (\S+) \s* (.*) $/ {
            my $version   = $0.Int;
            my $timestamp = ~$1;
            my $hostname  = ~$2;
            my $app-name  = ~$3;
            my $procid    = ~$4;
            my $msgid     = ~$5;
            my $rest      = ~$6;

            $fl.add(Sigil::Core::IntField.new(:name("Version"), :key("syslog.version"), :value($version)));
            $fl.add(Sigil::Core::StringField.new(:name("Timestamp"), :key("syslog.timestamp"), :value($timestamp)));
            $fl.add(Sigil::Core::StringField.new(:name("Hostname"), :key("syslog.hostname"), :value($hostname)));
            $fl.add(Sigil::Core::StringField.new(:name("App Name"), :key("syslog.app_name"), :value($app-name)));
            $fl.add(Sigil::Core::StringField.new(:name("Process ID"), :key("syslog.procid"), :value($procid)));
            $fl.add(Sigil::Core::StringField.new(:name("Message ID"), :key("syslog.msgid"), :value($msgid)));
            $fl.add(Sigil::Core::StringField.new(:name("Message Body"), :key("syslog.msg"), :value($rest)));

            $disp = sprintf("Syslog RFC 5424 [%s.%s] %s: %s", %facilities{$facility} // $facility, %severities{$severity} // $severity, $app-name, $rest.substr(0, 32));
        } else {
            # RFC 3164 BSD Syslog format fallback
            $fl.add(Sigil::Core::StringField.new(:name("Raw Message"), :key("syslog.msg"), :value($body)));
            $disp = sprintf("Syslog RFC 3164 [%s.%s] %s", %facilities{$facility} // $facility, %severities{$severity} // $severity, $body.substr(0, 32));
        }
    } else {
        $status = STATUS_MALFORMED;
        $disp = "Syslog (Non-compliant format)";
    }

    return Sigil::Core::Layer.new(
        :name("Syslog"),
        :display-name($disp),
        :offset($offset),
        :header-length($slice.elems),
        :payload-length(0),
        :raw-header($slice),
        :raw-payload(Buf.new),
        :fields($fl),
        :status($status),
        :next-protocol(Nil)
    );
}
