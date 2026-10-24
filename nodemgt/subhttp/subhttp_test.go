package subhttp

import "testing"

func TestNormalizePathAndToken(t *testing.T) {
	if got := NormalizePath("abc"); got != "/abc/" {
		t.Fatalf("path %q", got)
	}
	token, ok := TokenFromPath("/a1b2c3/tok", "/a1b2c3/")
	if !ok || token != "tok" {
		t.Fatalf("token %q %v", token, ok)
	}
	if _, ok := TokenFromPath("/sub/tok", "/a1b2c3/"); ok {
		t.Fatal("wrong prefix matched")
	}
	if _, ok := TokenFromPath("/a1b2c3/tok/extra", "/a1b2c3/"); ok {
		t.Fatal("nested path matched")
	}
}

func TestPublicURLOmitsDomainWhenHostEmpty(t *testing.T) {
	cfg := Config{ListenPort: 2096, Path: "/s3cret/", PublicHost: ""}
	if got := PublicURL(cfg, "tok"); got != "/s3cret/tok" {
		t.Fatalf("path only: %q", got)
	}
	cfg.PublicHost = "203.0.113.9"
	if got := PublicURL(cfg, "tok"); got != "http://203.0.113.9:2096/s3cret/tok" {
		t.Fatalf("ip url: %q", got)
	}
	cfg.PublicHost = "https://sub.example.net"
	cfg.ListenPort = 0
	if got := PublicURL(cfg, "tok"); got != "https://sub.example.net/s3cret/tok" {
		t.Fatalf("https host: %q", got)
	}
	cfg.PublicHost = "203.0.113.9"
	cfg.ListenPort = 2096
	cfg.PublicPort = 443
	if got := PublicURL(cfg, "tok"); got != "http://203.0.113.9:443/s3cret/tok" {
		t.Fatalf("reverse proxy port: %q", got)
	}
}
