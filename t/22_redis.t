# Test suite for Sigil::Grammar::Protocol::Redis
use Test;
use Sigil::Grammar::Protocol::Redis;
use Sigil::Types;

plan 11;

# Redis command: *3\r\n$3\r\nSET\r\n$9\r\nuser:1001\r\n$5\r\nalice\r\n
my $redis_set_str = "*3\r\n\$3\r\nSET\r\n\$9\r\nuser:1001\r\n\$5\r\nalice\r\n";
my $redis_set_raw = Buf.new($redis_set_str.encode('ascii'));

my $layer = Sigil::Grammar::Protocol::Redis.dissect($redis_set_raw);
is $layer.name, "Redis", "Layer identified as Redis";
is $layer.status, STATUS_OK, "Status is OK";
is $layer.val("redis.type"), "Array", "Type is Array";
is $layer.val("redis.array_len"), 3, "Array length is 3";
is $layer.val("redis.command"), "SET", "Command verb extracted as SET";
is $layer.val("redis.key"), "user:1001", "Key extracted as user:1001";
ok $layer.display-name.contains("SET user:1001"), "Display name contains command and key";

# Redis Simple String: +OK\r\n
my $redis_ok = Buf.new("+OK\r\n".encode('ascii'));
my $l_ok = Sigil::Grammar::Protocol::Redis.dissect($redis_ok);
is $l_ok.val("redis.value"), "OK", "Simple string value parsed as 'OK'";

# Redis Integer: :1000\r\n
my $redis_int = Buf.new(":1000\r\n".encode('ascii'));
my $l_int = Sigil::Grammar::Protocol::Redis.dissect($redis_int);
is $l_int.val("redis.integer"), 1000, "Integer value parsed as 1000";

# Redis Null Bulk String: $-1\r\n
my $redis_null = Buf.new("\$-1\r\n".encode('ascii'));
my $l_null = Sigil::Grammar::Protocol::Redis.dissect($redis_null);
is $l_null.val("redis.bulk_string"), "nil", "Null bulk string parsed as nil";

# Truncated RESP
my $trunc_raw = Buf.new(0x2a);
my $l_trunc = Sigil::Grammar::Protocol::Redis.dissect($trunc_raw);
is $l_trunc.status, STATUS_TRUNCATED, "Truncated RESP yields STATUS_TRUNCATED";
