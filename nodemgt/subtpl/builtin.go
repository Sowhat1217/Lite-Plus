package subtpl

import "github.com/nuomiiiii/lite/nodemgt/models"

const clashDefault = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    include-all: true
    proxies: [DIRECT]
rules:
  - MATCH,PROXY
`

const loonDefault = `[General]
ip-mode = v4-only
dns-server = system
allow-wifi-access = false

[Proxy]

[Proxy Group]
PROXY = select, __PROXY_NODES__

[Rule]
FINAL,PROXY
`

const surgeDefault = `[General]
loglevel = notify
dns-server = system

[Proxy]

[Proxy Group]
PROXY = select, __PROXY_NODES__

[Rule]
FINAL,PROXY
`

const singBoxDefault = `{
  "log": {"level": "info"},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}],
  "outbounds": [
    {"type": "selector", "tag": "PROXY", "outbounds": ["__PROXY_NODES__", "DIRECT"]},
    {"type": "direct", "tag": "DIRECT"}
  ],
  "route": {"final": "PROXY"}
}`

func BuiltinTemplates() []models.SubscriptionTemplate {
	return []models.SubscriptionTemplate{
		{ID: "builtin-clash", Name: "Mihomo / Clash", Kind: "clash", Content: clashDefault, Revision: 1},
		{ID: "builtin-loon", Name: "Loon", Kind: "loon", Content: loonDefault, Revision: 1},
		{ID: "builtin-surge", Name: "Surge", Kind: "surge", Content: surgeDefault, Revision: 1},
		{ID: "builtin-sing-box", Name: "sing-box", Kind: "sing-box", Content: singBoxDefault, Revision: 1},
	}
}

func DefaultTemplate(kind string) models.SubscriptionTemplate {
	for _, tpl := range BuiltinTemplates() {
		if tpl.Kind == kind {
			return tpl
		}
	}
	return models.SubscriptionTemplate{}
}
