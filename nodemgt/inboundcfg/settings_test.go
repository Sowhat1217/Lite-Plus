package inboundcfg

import (
	"encoding/json"
	"testing"
)

func TestListenForStack(t *testing.T) {
	if got := ListenForStack("ipv4", ""); got != "0.0.0.0" {
		t.Fatalf("ipv4 listen %s", got)
	}
	if got := ListenForStack("ipv6", ""); got != "::" {
		t.Fatalf("ipv6 listen %s", got)
	}
	if got := ListenForStack("dual", ""); got != "0.0.0.0,::" {
		t.Fatalf("dual listen %s", got)
	}
	if got := ListenForStack("", ""); got != "0.0.0.0,::" {
		t.Fatalf("empty stack listen %s", got)
	}
	if got := ListenForStack("ipv4", "[::]"); got != "0.0.0.0" {
		t.Fatalf("ipv4 wildcard [::] %s", got)
	}
	if got := ListenForStack("dual", "192.0.2.8"); got != "192.0.2.8" {
		t.Fatalf("keep explicit listen %s", got)
	}
}

func TestFrontListenHosts(t *testing.T) {
	dual := FrontListenHosts("dual", "")
	if len(dual) != 2 || dual[0] != "0.0.0.0" || dual[1] != "::" {
		t.Fatalf("dual hosts %v", dual)
	}
	legacy := FrontListenHosts("dual", "::")
	if len(legacy) != 2 || legacy[0] != "0.0.0.0" || legacy[1] != "::" {
		t.Fatalf("legacy dual listen=:: %v", legacy)
	}
	ipv4 := FrontListenHosts("ipv4", "")
	if len(ipv4) != 1 || ipv4[0] != "0.0.0.0" {
		t.Fatalf("ipv4 hosts %v", ipv4)
	}
	if containsSlice(ipv4, "::") {
		t.Fatalf("ipv4 hosts must not include ::: %v", ipv4)
	}
	fromV6Wildcard := FrontListenHosts("ipv4", "[::]")
	if len(fromV6Wildcard) != 1 || fromV6Wildcard[0] != "0.0.0.0" {
		t.Fatalf("ipv4 from [::] %v", fromV6Wildcard)
	}
	if got := FrontListenHosts("dual", "192.0.2.8"); len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("explicit IP %v", got)
	}
}

func containsSlice(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestGenerateRealityKeys(t *testing.T) {
	priv, pub, err := GenerateRealityKeys()
	if err != nil || priv == "" || pub == "" || priv == pub {
		t.Fatalf("keys priv=%q pub=%q err=%v", priv, pub, err)
	}
}

func TestDefaultCoreAnyTLS(t *testing.T) {
	if got := DefaultCore("anytls"); got != "sing-box" {
		t.Fatalf("anytls core %s", got)
	}
	if got := DefaultTransport("anytls"); got != "tcp" {
		t.Fatalf("anytls transport %s", got)
	}
	if got := DefaultSecurity("anytls"); got != "tls" {
		t.Fatalf("anytls security %s", got)
	}
}

func TestDefaultSSMethodIs2022(t *testing.T) {
	if got := DefaultSSMethod(); got != "2022-blake3-aes-128-gcm" {
		t.Fatalf("default ss method %s", got)
	}
}

func TestShadowsocksForcesTCPAndDropsHTTPHeader(t *testing.T) {
	raw := StreamJSON(Settings{Transport: "ws", Security: "reality", TCPHeader: "http", TCPHost: "example.com"}, "shadowsocks")
	var stream map[string]any
	if err := json.Unmarshal([]byte(raw), &stream); err != nil {
		t.Fatal(err)
	}
	if stream["network"] != "tcp" {
		t.Fatalf("network %v in %s", stream["network"], raw)
	}
	if stream["security"] == "reality" {
		t.Fatalf("reality leaked: %s", raw)
	}
	if _, ok := stream["tcpSettings"]; ok {
		t.Fatalf("tcp camouflage leaked: %s", raw)
	}
}

func TestNormalizeAccountsDropsBlankAndDuplicates(t *testing.T) {
	got := NormalizeAccounts([]ProxyAccount{
		{User: " a ", Pass: "1"},
		{User: "", Pass: "x"},
		{User: "a", Pass: "2"},
		{User: "b", Pass: ""},
	})
	if len(got) != 1 || got[0].User != "a" || got[0].Pass != "1" {
		t.Fatalf("got %#v", got)
	}
}

func TestHTTPForcesTCPAndRejectsReality(t *testing.T) {
	if got := DefaultCore("http"); got != "xray" {
		t.Fatalf("http core %s", got)
	}
	if got := DefaultTransport("http"); got != "tcp" {
		t.Fatalf("http transport %s", got)
	}
	raw := StreamJSON(Settings{Transport: "ws", Security: "reality"}, "http")
	var stream map[string]any
	if err := json.Unmarshal([]byte(raw), &stream); err != nil {
		t.Fatal(err)
	}
	if stream["network"] != "tcp" {
		t.Fatalf("network %v in %s", stream["network"], raw)
	}
	if stream["security"] == "reality" {
		t.Fatalf("reality leaked: %s", raw)
	}
}

func TestNormalizeShareStrategy(t *testing.T) {
	cases := map[string]string{
		"":            "node",
		"node":        "node",
		"listen":      "listen",
		"other":       "other",
		"specified":   "other",
		"Specified":   "other",
		"none":        "none",
		" unexpected": "node",
	}
	for raw, want := range cases {
		if got := NormalizeShareStrategy(raw); got != want {
			t.Fatalf("%q: got %q want %q", raw, got, want)
		}
	}
}

func TestDestHost(t *testing.T) {
	if got := DestHost("www.microsoft.com:443"); got != "www.microsoft.com" {
		t.Fatalf("dest host %s", got)
	}
}

func TestStreamJSONReality(t *testing.T) {
	raw := StreamJSON(Settings{
		Stack:              "dual",
		Transport:          "tcp",
		Security:           "reality",
		RealityDest:        "www.cloudflare.com:443",
		RealityServerNames: "www.cloudflare.com",
		RealityShortID:     "12ab",
		Fingerprint:        "chrome",
		SpiderX:            "/",
	}, "vless")
	if raw == "{}" || !containsAll(raw, []string{`"security":"reality"`, `"stack":"dual"`, `"dest":"www.cloudflare.com:443"`, `"target":"www.cloudflare.com:443"`, "www.cloudflare.com"}) {
		t.Fatalf("stream %s", raw)
	}
	if contains(raw, "v6only") || contains(raw, `"sockopt"`) {
		t.Fatalf("stream must not set v6only sockopt, got %s", raw)
	}
	if contains(raw, "certId") || contains(raw, "privateKey") || contains(raw, "publicKey") {
		t.Fatalf("REALITY must not bind a node cert or leak empty keys, got %s", raw)
	}
}

func TestStreamJSONWebSocket(t *testing.T) {
	raw := StreamJSON(Settings{Transport: "ws", WSPath: "/vless", WSHost: "cdn.example.com"}, "vless")
	if !containsAll(raw, []string{`"network":"ws"`, `"/vless"`, "cdn.example.com"}) {
		t.Fatalf("ws stream %s", raw)
	}
}

func TestSniffingJSON(t *testing.T) {
	if SniffingJSON(Settings{}) != nil {
		t.Fatal("sniffing off should omit the block")
	}
	got := SniffingJSON(Settings{Sniffing: true, RouteOnly: true})
	raw, _ := json.Marshal(got)
	if !containsAll(string(raw), []string{`"enabled":true`, `"http"`, `"tls"`, `"quic"`, `"routeOnly":true`}) {
		t.Fatalf("sniffing %s", raw)
	}
}

func TestShareSNIPrefersRealityDestOverLeftoverTLS(t *testing.T) {
	got := ShareSNI(Settings{
		Security:           "reality",
		SNI:                "ppfla.8787837.xyz",
		TLSDomain:          "ppfla.8787837.xyz",
		RealityDest:        "addons.mozilla.org:443",
		RealityServerNames: "addons.mozilla.org",
	})
	if got != "addons.mozilla.org" {
		t.Fatalf("share sni %q", got)
	}
	if got := ShareSNI(Settings{Security: "tls", SNI: "edge.example.com"}); got != "edge.example.com" {
		t.Fatalf("tls sni %q", got)
	}
	if got := ShareSNI(Settings{Security: "reality", SNI: "left.over", RealityDest: "www.microsoft.com:443"}); got != "www.microsoft.com" {
		t.Fatalf("reality dest fallback %q", got)
	}
}

func TestRealitySniffingForcesRouteOnly(t *testing.T) {
	s := Settings{Sniffing: true, Security: "reality", Flow: "xtls-rprx-vision"}
	if !EffectiveRouteOnly(s) {
		t.Fatal("reality sniffing must be route-only")
	}
	got := SniffingJSON(s)
	raw, _ := json.Marshal(got)
	if !containsAll(string(raw), []string{`"routeOnly":true`}) {
		t.Fatalf("sniffing %s", raw)
	}
	normalized := NormalizeSniffSettingsJSON(`{"sniffing":true,"security":"reality","dest_override":"http,tls,quic"}`)
	if !contains(normalized, `"route_only":true`) {
		t.Fatalf("normalize %s", normalized)
	}
	if off := NormalizeSniffSettingsJSON(`{"security":"reality"}`); contains(off, `"route_only"`) {
		t.Fatalf("sniffing off should stay off: %s", off)
	}
}

func containsAll(raw string, parts []string) bool {
	for _, p := range parts {
		if !contains(raw, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || search(s, sub))
}

func search(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
