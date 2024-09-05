use v6.d;
use Test;
use Sigil::Types;
use Sigil::Core::Field;
use Sigil::Grammar::Protocol::DNSSEC;

plan 10;

# 1. DNSKEY RDATA parsing
{
    # Flags = 0x0101 (Zone Key + SEP = KSK), Proto = 3, Algo = 13 (ECDSA P-256)
    my @b = (0x01, 0x01, 0x03, 0x0D);
    @b.append(1..32); # 32-byte public key
    my $fl = Sigil::Grammar::Protocol::DNSSEC::parse-dnskey(Buf.new(@b));

    is $fl.get("dnssec.dnskey.flags").value, 0x0101, "DNSKEY flags is 0x0101";
    ok $fl.get("dnssec.dnskey.is_zone_key").value, "Zone Key flag is set";
    ok $fl.get("dnssec.dnskey.is_sep").value, "Secure Entry Point (SEP) flag is set";
    is $fl.get("dnssec.dnskey.protocol").value, 3, "DNSSEC protocol value is 3";
    is $fl.get("dnssec.dnskey.algorithm").value, 13, "Algorithm is 13 (ECDSA P-256)";
}

# 2. DS RDATA parsing
{
    # KeyTag = 60485 (0xEC45), Algo = 13, DigestType = 2 (SHA-256)
    my @b = (0xEC, 0x45, 0x0D, 0x02);
    @b.append(1..32); # SHA-256 digest
    my $fl = Sigil::Grammar::Protocol::DNSSEC::parse-ds(Buf.new(@b));

    is $fl.get("dnssec.ds.keytag").value, 60485, "DS key tag matches 60485";
    is $fl.get("dnssec.ds.algorithm").value, 13, "DS algorithm is 13";
    is $fl.get("dnssec.ds.digest_type").value, 2, "DS digest type is SHA-256 (2)";
}

# 3. RRSIG RDATA parsing
{
    # TypeCovered = 1 (A), Algo = 13, Labels = 2, TTL = 3600
    my @b = (
        0x00, 0x01, # Type Covered (A)
        0x0D,       # Algorithm (13)
        0x02,       # Labels (2)
        0x00, 0x00, 0x0E, 0x10, # Original TTL (3600)
        0x65, 0x00, 0x00, 0x00, # Expiration
        0x64, 0xF0, 0x00, 0x00, # Inception
        0x12, 0x34  # Key Tag
    );
    my $fl = Sigil::Grammar::Protocol::DNSSEC::parse-rrsig(Buf.new(@b));

    is $fl.get("dnssec.rrsig.type_covered").value, 1, "RRSIG covers Type A (1)";
    is $fl.get("dnssec.rrsig.labels").value, 2, "RRSIG labels count is 2";
}

done-testing;
