package jsonrpc

import "testing"

func TestFillRealityInboundDefaultsKeepsEmptyFlow(t *testing.T) {
	p := inboundUpsertParams{
		Protocol: "vless",
		Security: "reality",
		Flow:     "",
	}
	if err := fillRealityInboundDefaults(&p); err != nil {
		t.Fatal(err)
	}
	if p.Flow != "" {
		t.Fatalf("empty flow was overwritten: %q", p.Flow)
	}
	if p.Transport != "tcp" {
		t.Fatalf("transport: %q", p.Transport)
	}
	if p.RealityDest == "" || p.RealityServerNames == "" || p.Fingerprint == "" {
		t.Fatalf("missing reality defaults: %+v", p)
	}
}

func TestFillRealityInboundDefaultsKeepsChosenFlow(t *testing.T) {
	p := inboundUpsertParams{
		Protocol: "vless",
		Security: "reality",
		Flow:     "xtls-rprx-vision-udp443",
	}
	if err := fillRealityInboundDefaults(&p); err != nil {
		t.Fatal(err)
	}
	if p.Flow != "xtls-rprx-vision-udp443" {
		t.Fatalf("chosen flow: %q", p.Flow)
	}
}
