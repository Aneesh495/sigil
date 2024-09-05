# Sigil::Grammar::Protocol::DNSSEC - DNS Security Extensions dissector (RFC 4034)
#
# Decodes cryptographic DNSSEC Resource Records: RRSIG, DNSKEY, DS, and NSEC/NSEC3.

unit class Sigil::Grammar::Protocol::DNSSEC;

use Sigil::Types;
use Sigil::Core::Buffer;
use Sigil::Core::Field;
use Sigil::Core::Layer;

our constant RRTYPE_DS     = 43;
our constant RRTYPE_RRSIG  = 46;
our constant RRTYPE_NSEC   = 47;
our constant RRTYPE_DNSKEY = 48;
our constant RRTYPE_NSEC3  = 50;

method protocol-name(--> Str) { return "DNSSEC"; }

# Decode DNSKEY RDATA
our sub parse-dnskey(Buf $rdata --> Sigil::Core::FieldList) is export {
    my $fl = Sigil::Core::FieldList.new;
    return $fl if $rdata.elems < 4;

    my $buf = Sigil::Core::Buffer.new($rdata);
    my $flags = $buf.read-uint16-be();
    my $proto = $buf.read-uint8();
    my $algo  = $buf.read-uint8();
    my $pubkey = $buf.read-remaining();

    $fl.add(Sigil::Core::IntField.new(:name("Flags"), :key("dnssec.dnskey.flags"), :value($flags), :radix("hex"), :bit-width(16)));
    $fl.add(Sigil::Core::FlagField.new(:name("Zone Key (ZK)"), :key("dnssec.dnskey.is_zone_key"), :mask(0x0100), :is-set(($flags +& 0x0100) != 0)));
    $fl.add(Sigil::Core::FlagField.new(:name("Secure Entry Point (SEP)"), :key("dnssec.dnskey.is_sep"), :mask(0x0001), :is-set(($flags +& 0x0001) != 0)));
    $fl.add(Sigil::Core::IntField.new(:name("Protocol"), :key("dnssec.dnskey.protocol"), :value($proto)));
    $fl.add(Sigil::Core::IntField.new(:name("Algorithm"), :key("dnssec.dnskey.algorithm"), :value($algo)));
    $fl.add(Sigil::Core::BytesField.new(:name("Public Key"), :key("dnssec.dnskey.pubkey"), :bytes($pubkey)));

    return $fl;
}

# Decode DS (Delegation Signer) RDATA
our sub parse-ds(Buf $rdata --> Sigil::Core::FieldList) is export {
    my $fl = Sigil::Core::FieldList.new;
    return $fl if $rdata.elems < 4;

    my $buf = Sigil::Core::Buffer.new($rdata);
    my $keytag = $buf.read-uint16-be();
    my $algo   = $buf.read-uint8();
    my $digest-type = $buf.read-uint8();
    my $digest = $buf.read-remaining();

    $fl.add(Sigil::Core::IntField.new(:name("Key Tag"), :key("dnssec.ds.keytag"), :value($keytag)));
    $fl.add(Sigil::Core::IntField.new(:name("Algorithm"), :key("dnssec.ds.algorithm"), :value($algo)));
    $fl.add(Sigil::Core::IntField.new(:name("Digest Type"), :key("dnssec.ds.digest_type"), :value($digest-type)));
    $fl.add(Sigil::Core::BytesField.new(:name("Digest"), :key("dnssec.ds.digest"), :bytes($digest)));

    return $fl;
}

# Decode RRSIG RDATA
our sub parse-rrsig(Buf $rdata --> Sigil::Core::FieldList) is export {
    my $fl = Sigil::Core::FieldList.new;
    return $fl if $rdata.elems < 18;

    my $buf = Sigil::Core::Buffer.new($rdata);
    my $type-covered = $buf.read-uint16-be();
    my $algo         = $buf.read-uint8();
    my $labels       = $buf.read-uint8();
    my $orig-ttl     = $buf.read-uint32-be();
    my $sig-exp      = $buf.read-uint32-be();
    my $sig-inc      = $buf.read-uint32-be();
    my $keytag       = $buf.read-uint16-be();

    $fl.add(Sigil::Core::IntField.new(:name("Type Covered"), :key("dnssec.rrsig.type_covered"), :value($type-covered)));
    $fl.add(Sigil::Core::IntField.new(:name("Algorithm"), :key("dnssec.rrsig.algorithm"), :value($algo)));
    $fl.add(Sigil::Core::IntField.new(:name("Labels"), :key("dnssec.rrsig.labels"), :value($labels)));
    $fl.add(Sigil::Core::IntField.new(:name("Original TTL"), :key("dnssec.rrsig.orig_ttl"), :value($orig-ttl)));
    $fl.add(Sigil::Core::IntField.new(:name("Signature Expiration"), :key("dnssec.rrsig.expiration"), :value($sig-exp)));
    $fl.add(Sigil::Core::IntField.new(:name("Signature Inception"), :key("dnssec.rrsig.inception"), :value($sig-inc)));
    $fl.add(Sigil::Core::IntField.new(:name("Key Tag"), :key("dnssec.rrsig.keytag"), :value($keytag)));

    return $fl;
}
