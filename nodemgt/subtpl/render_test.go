package subtpl

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/sub"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestClientSelectionAndLegacyCompatibility(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"Loon/3.0", "loon"}, {"Surge Mac/6.0", "surge-mac"}, {"Surge/5", "surge"},
		{"Stash/2", "stash"}, {"mihomo/1.19", "mihomo"}, {"Clash.Meta/1", "mihomo"},
		{"Clash/1.0", "clash"}, {"sing-box/1.14", "sing-box"}, {"v2rayN/7", "v2ray"},
		{"Shadowrocket/2", "v2ray"}, {"Mozilla/5.0", ""},
	} {
		require.Equal(t, tc.want, DetectClient(tc.ua), tc.ua)
	}
	selected, err := ResolveTarget("surge", "clash", "Loon/3", "xray", true)
	require.NoError(t, err)
	require.Equal(t, "surge", selected.Client)
	require.Empty(t, selected.LegacyFormat)
	selected, err = ResolveTarget("", "clash", "Loon/3", "xray", true)
	require.NoError(t, err)
	require.Equal(t, "clash", selected.LegacyFormat)
	selected, err = ResolveTarget("", "", "Loon/3", "xray", false)
	require.NoError(t, err)
	require.Equal(t, "xray", selected.LegacyFormat)
	selected, err = ResolveTarget("", "", "Loon/3", "xray", true)
	require.NoError(t, err)
	require.Equal(t, "loon", selected.Client)
	require.Empty(t, selected.LegacyFormat)
	selected, err = ResolveTarget("", "", "unknown", "xray", true)
	require.NoError(t, err)
	require.Equal(t, "xray", selected.LegacyFormat)
	_, err = ResolveTarget("unknown", "", "", "xray", true)
	require.Error(t, err)
}

func exampleNodes() []sub.Node {
	return []sub.Node{
		{Name: "HK Trojan", Protocol: "trojan", Host: "hk.example.com", Port: 443, Password: "test-pass", Security: "tls", SNI: "hk.example.com", Type: "tcp"},
		{Name: "JP VLESS", Protocol: "vless", Host: "jp.example.com", Port: 443, UUID: "00000000-0000-4000-8000-000000000001", Security: "reality", PublicKey: "public-key", ShortID: "ab12", Flow: "xtls-rprx-vision", Type: "tcp"},
	}
}

func TestEveryBuiltinRendersCompleteConfig(t *testing.T) {
	for _, client := range []string{"mihomo", "clash", "stash", "loon", "surge", "surge-mac", "sing-box"} {
		t.Run(client, func(t *testing.T) {
			kind := client
			if client == "mihomo" || client == "stash" {
				kind = "clash"
			}
			if client == "surge-mac" {
				kind = "surge"
			}
			doc, err := Render(client, DefaultTemplate(kind), exampleNodes(), nil)
			require.NoError(t, err)
			require.NotEmpty(t, doc.Body)
			require.Contains(t, doc.Body, "hk.example.com")
			require.NotContains(t, doc.Body, "__PROXY_NODES__")
			switch kind {
			case "clash":
				var root map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(doc.Body), &root))
				require.NotEmpty(t, root["proxy-groups"])
				require.NotEmpty(t, root["rules"])
			case "sing-box":
				var root map[string]any
				require.NoError(t, json.Unmarshal([]byte(doc.Body), &root))
				require.NotEmpty(t, root["route"])
			default:
				require.Contains(t, doc.Body, "[Rule]")
			}
		})
	}
}

func TestV3FilteringAndSanitizedEmbeddedNodes(t *testing.T) {
	tpl := models.SubscriptionTemplate{Kind: "clash", Content: `dns:
  enable: true
  nameserver: [https://dns.example.com/dns-query]
proxies:
  - {name: leaked, type: trojan, server: secret.invalid, port: 443, password: leaked-secret}
proxy-groups:
  - {name: HK, type: select, include-all: true, filter: HK, proxies: [DIRECT]}
rule-providers:
  private: {type: http, behavior: domain, url: "https://rules.example.com/private.yaml", path: ./rules/private.yaml}
rules: ["MATCH,HK"]
`}
	doc, err := Render("mihomo", tpl, exampleNodes(), nil)
	require.NoError(t, err)
	require.NotContains(t, doc.Body, "leaked-secret")
	require.NotContains(t, doc.Body, "secret.invalid")
	require.Contains(t, doc.Body, "hk.example.com")
	require.NotContains(t, doc.Body, "jp.example.com")
	require.Contains(t, doc.Body, "dns.example.com")
	require.Contains(t, doc.Body, "rules.example.com")
	require.NotContains(t, doc.Body, "include-all")
}

func TestNativeTemplatePreservesRulesAndRemovesStaticCredentials(t *testing.T) {
	for _, kind := range []string{"loon", "surge"} {
		tpl := DefaultTemplate(kind)
		tpl.Content = strings.Replace(tpl.Content, "[Proxy]", "[Proxy]\nleaked = trojan, secret.invalid, 443, password=leaked-secret", 1)
		tpl.Content += "\nDOMAIN-SUFFIX,emby.example,PROXY\n"
		doc, err := Render(kind, tpl, exampleNodes(), nil)
		require.NoError(t, err)
		require.NotContains(t, doc.Body, "leaked-secret")
		require.Contains(t, doc.Body, "DOMAIN-SUFFIX,emby.example,PROXY")
	}
}

func TestUnsupportedTransportIsFilteredAndReported(t *testing.T) {
	nodes := append(exampleNodes(), sub.Node{Name: "XHTTP", Protocol: "vless", Host: "xhttp.invalid", Port: 443, UUID: "test", Type: "xhttp"})
	for _, client := range []string{"mihomo", "loon", "surge", "sing-box"} {
		kind := client
		if client == "mihomo" {
			kind = "clash"
		}
		doc, err := Render(client, DefaultTemplate(kind), nodes, nil)
		require.NoError(t, err)
		require.NotContains(t, doc.Body, "xhttp.invalid")
		require.NotEmpty(t, doc.Warnings)
	}
}

func TestEmptyConfigAndInvalidTemplates(t *testing.T) {
	for _, kind := range []string{"clash", "loon", "surge", "sing-box"} {
		client := kind
		if kind == "clash" {
			client = "mihomo"
		}
		doc, err := Render(client, DefaultTemplate(kind), nil, nil)
		require.NoError(t, err)
		require.Contains(t, doc.Body, "DIRECT")
	}
	_, err := Prepare("clash", "- invalid-root")
	require.Error(t, err)
	_, err = Prepare("clash", "proxy-providers:\n  secret: {url: https://secret.invalid/token}\n")
	require.Error(t, err)
	_, err = Prepare("sing-box", "null")
	require.Error(t, err)
	_, err = Prepare("surge", "[General]\n")
	require.Error(t, err)
}

func TestHTTPUpgradeIsPreservedForSingBoxAndFilteredForLoon(t *testing.T) {
	nodes := []sub.Node{{Name: "Upgrade", Protocol: "vless", Host: "upgrade.example", Port: 443, UUID: "00000000-0000-4000-8000-000000000001", Type: "httpupgrade", Path: "/upgrade", HostHeader: "front.example"}}
	doc, err := Render("sing-box", DefaultTemplate("sing-box"), nodes, nil)
	require.NoError(t, err)
	require.Contains(t, doc.Body, `"type": "httpupgrade"`)
	require.Contains(t, doc.Body, "/upgrade")
	doc, err = Render("loon", DefaultTemplate("loon"), nodes, nil)
	require.NoError(t, err)
	require.NotContains(t, doc.Body, "upgrade.example")
	require.Len(t, doc.Warnings, 1)
}

func TestInvalidPolicyReferencesAreRejected(t *testing.T) {
	tpl := DefaultTemplate("clash")
	tpl.Content = strings.ReplaceAll(tpl.Content, "MATCH,PROXY", "MATCH,missing")
	_, err := Render("mihomo", tpl, exampleNodes(), nil)
	require.ErrorContains(t, err, "unknown rule policy")
	tpl = DefaultTemplate("loon")
	tpl.Content = strings.ReplaceAll(tpl.Content, "__PROXY_NODES__", "missing")
	_, err = Render("loon", tpl, exampleNodes(), nil)
	require.ErrorContains(t, err, "unknown native policy")
	tpl = DefaultTemplate("sing-box")
	tpl.Content = strings.ReplaceAll(tpl.Content, `"final": "PROXY"`, `"final": "missing"`)
	_, err = Render("sing-box", tpl, exampleNodes(), nil)
	require.ErrorContains(t, err, "unknown final outbound")
}

func TestMiaoMiaoWuSingBoxAllMarker(t *testing.T) {
	const content = `{
		"dns": {"servers": [{"tag": "dns-proxy", "type": "https", "server": "1.1.1.1", "detour": "Manual"}]},
		"outbounds": [
			{"tag": "Manual", "type": "selector", "outbounds": ["Auto", "{all}"]},
			{"tag": "Auto", "type": "urltest", "outbounds": ["{all}"]},
			{"tag": "Custom direct", "type": "direct"}
		],
		"route": {"final": "Manual"}
	}`
	for _, tc := range []struct {
		name   string
		nodes  []sub.Node
		want   []string
		manual []string
	}{
		{"authorized nodes", exampleNodes(), []string{"HK Trojan", "JP VLESS"}, []string{"Auto", "HK Trojan", "JP VLESS"}},
		{"no nodes", nil, []string{"Custom direct"}, []string{"Auto"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Render("sing-box", models.SubscriptionTemplate{Kind: "sing-box", Content: content}, tc.nodes, nil)
			require.NoError(t, err)
			require.NotContains(t, doc.Body, "{all}")
			var root struct {
				Outbounds []struct {
					Tag       string   `json:"tag"`
					Outbounds []string `json:"outbounds"`
				} `json:"outbounds"`
			}
			require.NoError(t, json.Unmarshal([]byte(doc.Body), &root))
			require.Equal(t, tc.manual, root.Outbounds[0].Outbounds)
			require.Equal(t, tc.want, root.Outbounds[1].Outbounds)
			require.Contains(t, doc.Body, `"detour": "Manual"`)
		})
	}
}

func TestSingBoxEmptyGroupsReceiveValidDirectFallback(t *testing.T) {
	for _, marker := range []string{"{all}", "__PROXY_NODES__"} {
		tpl := models.SubscriptionTemplate{Kind: "sing-box", Content: fmt.Sprintf(`{
			"outbounds": [{"type": "selector", "tag": "DIRECT", "outbounds": ["%s"]}],
			"route": {"final": "DIRECT"}
		}`, marker)}
		doc, err := Render("sing-box", tpl, nil, nil)
		require.NoError(t, err)
		var root map[string]any
		require.NoError(t, json.Unmarshal([]byte(doc.Body), &root))
		outs := root["outbounds"].([]any)
		require.Len(t, outs, 2)
		require.Equal(t, []any{"DIRECT 2"}, outs[0].(map[string]any)["outbounds"])
		require.Equal(t, map[string]any{"tag": "DIRECT 2", "type": "direct"}, outs[1])
	}
}

func TestSurgeWarningIdentifiesUnsupportedNodeFeatures(t *testing.T) {
	doc, err := Render("surge", DefaultTemplate("surge"), exampleNodes()[1:], nil)
	require.NoError(t, err)
	require.Equal(t, []string{"JP VLESS: unsupported by surge (vless/reality)"}, doc.Warnings)
	require.NotContains(t, doc.Body, "jp.example.com")
	require.Contains(t, doc.Body, "PROXY = select, DIRECT")
}
