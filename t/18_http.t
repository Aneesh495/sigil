# Test suite for Sigil::Grammar::Protocol::HTTP
use Test;
use Sigil::Grammar::Protocol::HTTP;
use Sigil::Types;

plan 14;

# HTTP GET Request
my $req_str = "GET /api/v1/telemetry HTTP/1.1\r\nHost: api.sigil.internal\r\nUser-Agent: SigilEngine/1.0\r\nAccept: application/json\r\n\r\n";
my $req_raw = Buf.new($req_str.encode('ascii'));

my $layer_req = Sigil::Grammar::Protocol::HTTP.dissect($req_raw);
is $layer_req.name, "HTTP", "Layer identified as HTTP";
is $layer_req.status, STATUS_OK, "Status is OK";
is $layer_req.val("http.request.method"), "GET", "Method is GET";
is $layer_req.val("http.request.uri"), "/api/v1/telemetry", "URI parsed";
is $layer_req.val("http.request.version"), "HTTP/1.1", "Version parsed as HTTP/1.1";
is $layer_req.val("http.host"), "api.sigil.internal", "Host header extracted";
ok $layer_req.display-name.contains("GET /api/v1/telemetry"), "Display name contains method and URI";

# HTTP Response (200 OK with Content-Length and JSON body)
my $resp_str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nServer: Sigil/1.0\r\n\r\n" ~ '{"status":"live"}';
my $resp_raw = Buf.new($resp_str.encode('ascii'));

my $layer_resp = Sigil::Grammar::Protocol::HTTP.dissect($resp_raw);
is $layer_resp.val("http.response.code"), 200, "Response code parsed as 200";
is $layer_resp.val("http.response.phrase"), "OK", "Reason phrase parsed as OK";
is $layer_resp.val("http.content_type"), "application/json", "Content-Type header extracted";
is $layer_resp.val("http.content_length"), 17, "Content-Length parsed as 17";
is $layer_resp.payload-length, 17, "Payload length matches Content-Length";
ok $layer_resp.display-name.contains("200 OK"), "Display name contains status code and phrase";

# Truncated HTTP input (< 8 bytes)
my $trunc_raw = Buf.new("GET".encode('ascii'));
my $layer_trunc = Sigil::Grammar::Protocol::HTTP.dissect($trunc_raw);
is $layer_trunc.status, STATUS_TRUNCATED, "Truncated HTTP yields STATUS_TRUNCATED";
