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
	cfg.CertPath = "./data/tls/server.crt"
	cfg.KeyPath = "./data/tls/server.key"
	cfg.Domain = "sub.example.com"
	cfg.PublicHost = "203.0.113.9"
	if got := PublicURL(cfg, "tok"); got != "https://203.0.113.9:443/s3cret/tok" {
		t.Fatalf("reuse https keeps public host: %q", got)
	}
	cfg.PublicHost = ""
	if got := PublicURL(cfg, "tok"); got != "/s3cret/tok" {
		t.Fatalf("reuse https without public host: %q", got)
	}
}

func TestApplyPanelHTTPSReusesCertificate(t *testing.T) {
	cfg := Config{ListenPort: 25111, Path: "/s3cret/", PublicHost: "127.0.0.1"}
	applyPanelHTTPS(&cfg, true, "./data/tls/server.crt", "./data/tls/server.key", []string{"abc.123.com"})
	if !cfg.ReuseHTTPS || cfg.CertPath != "./data/tls/server.crt" || cfg.Domain != "abc.123.com" {
		t.Fatalf("%+v", cfg)
	}
	if got := PublicURL(cfg, "tok"); got != "https://127.0.0.1:25111/s3cret/tok" {
		t.Fatalf("reuse url: %q", got)
	}
	applyPanelHTTPS(&cfg, false, "./data/tls/server.crt", "./data/tls/server.key", []string{"abc.123.com"})
	if cfg.ReuseHTTPS || cfg.CertPath != "" || cfg.Domain != "" {
		t.Fatalf("cleared %+v", cfg)
	}
	if err := (Config{ReuseHTTPS: true}).ValidateTLS(); err == nil {
		t.Fatal("reuse without cert should fail")
	}
}

func TestShareHostIgnoresCertificateDomain(t *testing.T) {
	cfg := Config{PublicHost: "203.0.113.9", Domain: "*.example.com", CertPath: "./c", KeyPath: "./k"}
	if got := cfg.shareHost(); got != "203.0.113.9" {
		t.Fatalf("public host %q", got)
	}
	cfg.PublicHost = ""
	if got := cfg.shareHost(); got != "" {
		t.Fatalf("empty host %q", got)
	}
}

func TestFirstShareDomainSkipsWildcard(t *testing.T) {
	if got := FirstShareDomain([]string{"*.example.com", "sub.example.com"}); got != "sub.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := FirstShareDomain([]string{"*.example.com"}); got != "example.com" {
		t.Fatalf("wildcard fallback %q", got)
	}
}
