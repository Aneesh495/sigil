# Sigil::Grammar::Protocol::LLDP - IEEE 802.1AB Link Layer Discovery Protocol dissector
#
# Decodes TLV chains for chassis identification, port assignment, device capabilities,
# and system descriptions across adjacent network switch fabrics.

unit class Sigil::Grammar::Protocol::LLDP;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;
use Sigil::Core::Error;

method protocol-name(--> Str) { return "LLDP"; }

our constant LLDP_TLV_END         = 0;
our constant LLDP_TLV_CHASSIS_ID  = 1;
our constant LLDP_TLV_PORT_ID     = 2;
our constant LLDP_TLV_TTL         = 3;
our constant LLDP_TLV_PORT_DESC   = 4;
our constant LLDP_TLV_SYS_NAME    = 5;
our constant LLDP_TLV_SYS_DESC    = 6;
our constant LLDP_TLV_SYS_CAP     = 7;
our constant LLDP_TLV_MGMT_ADDR   = 8;

# Dissect LLDPDU payload
method dissect(Buf $raw, Int :$offset = 0 --> Sigil::Core::Layer) {
    if $raw.elems - $offset < 4 {
        my $fl = Sigil::Core::FieldList.new;
        return Sigil::Core::Layer.new(
            :name("LLDP"),
            :display-name("LLDP (Truncated)"),
            :offset($offset),
            :header-length($raw.elems - $offset),
            :payload-length(0),
            :raw-header($raw.subbuf($offset)),
            :raw-payload(Buf.new),
            :fields($fl),
            :status(STATUS_TRUNCATED)
        );
    }

    my $buf = Sigil::Core::Buffer.new($raw, :offset($offset));
    my $start = $offset;
    my $fl = Sigil::Core::FieldList.new;

    my $sys-name = "";
    my $port-id = "";
    my $chassis-id = "";
    my $ttl = 0;

    while $buf.remaining >= 2 {
        my $tlv-header = $buf.read-uint16-be();
        my $type = ($tlv-header +> 9) +& 0x7F;
        my $len  = $tlv-header +& 0x01FF;

        if $type == LLDP_TLV_END {
            $fl.add(Sigil::Core::StringField.new(:name("TLV Type"), :key("lldp.tlv.end"), :value("End of LLDPDU")));
            last;
        }

        if $buf.remaining < $len {
            # Incomplete TLV
            last;
        }

        my $tlv-data = $buf.read-bytes($len);

        given $type {
            when LLDP_TLV_CHASSIS_ID {
                if $len >= 2 {
                    my $subtype = $tlv-data[0];
                    my $val-bytes = $tlv-data.subbuf(1);
                    $chassis-id = ($subtype == 4)
                        ?? sprintf("%02x:%02x:%02x:%02x:%02x:%02x", |$val-bytes.list)
                        !! $val-bytes.decode('ascii', :replacement<~>);
                    $fl.add(Sigil::Core::StringField.new(:name("Chassis ID"), :key("lldp.chassis.id"), :value($chassis-id)));
                    $fl.add(Sigil::Core::IntField.new(:name("Chassis Subtype"), :key("lldp.chassis.subtype"), :value($subtype)));
                }
            }
            when LLDP_TLV_PORT_ID {
                if $len >= 2 {
                    my $subtype = $tlv-data[0];
                    my $val-bytes = $tlv-data.subbuf(1);
                    $port-id = $val-bytes.decode('ascii', :replacement<~>);
                    $fl.add(Sigil::Core::StringField.new(:name("Port ID"), :key("lldp.port.id"), :value($port-id)));
                    $fl.add(Sigil::Core::IntField.new(:name("Port Subtype"), :key("lldp.port.subtype"), :value($subtype)));
                }
            }
            when LLDP_TLV_TTL {
                if $len >= 2 {
                    $ttl = ($tlv-data[0] +< 8) +| $tlv-data[1];
                    $fl.add(Sigil::Core::IntField.new(:name("Time to Live"), :key("lldp.ttl"), :value($ttl)));
                }
            }
            when LLDP_TLV_SYS_NAME {
                $sys-name = $tlv-data.decode('ascii', :replacement<~>);
                $fl.add(Sigil::Core::StringField.new(:name("System Name"), :key("lldp.system.name"), :value($sys-name)));
            }
            when LLDP_TLV_SYS_DESC {
                my $desc = $tlv-data.decode('ascii', :replacement<~>);
                $fl.add(Sigil::Core::StringField.new(:name("System Description"), :key("lldp.system.desc"), :value($desc)));
            }
            when LLDP_TLV_SYS_CAP {
                if $len >= 4 {
                    my $caps = ($tlv-data[0] +< 8) +| $tlv-data[1];
                    my $enabled = ($tlv-data[2] +< 8) +| $tlv-data[3];
                    $fl.add(Sigil::Core::IntField.new(:name("System Capabilities"), :key("lldp.system.caps"), :value($caps), :radix("hex")));
                    $fl.add(Sigil::Core::IntField.new(:name("Enabled Capabilities"), :key("lldp.system.enabled_caps"), :value($enabled), :radix("hex")));
                }
            }
            default {
                $fl.add(Sigil::Core::BytesField.new(:name("TLV Raw"), :key("lldp.tlv.data"), :bytes($tlv-data)));
            }
        }
    }

    my $header-len = $buf.offset - $start;
    my $disp = $sys-name ne ""
        ?? sprintf("LLDP: %s, Port: %s (TTL=%ds)", $sys-name, $port-id, $ttl)
        !! sprintf("LLDP: Chassis %s, Port %s", $chassis-id, $port-id);

    return Sigil::Core::Layer.new(
        :name("LLDP"),
        :display-name($disp),
        :offset($offset),
        :header-length($header-len),
        :payload-length(0),
        :raw-header($raw.subbuf($start, $header-len)),
        :raw-payload(Buf.new),
        :fields($fl),
        :status(STATUS_OK),
        :next-protocol(Nil)
    );
}
