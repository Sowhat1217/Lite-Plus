// Package subtpl adapts Lite's authorized nodes to the MiaoMiaoWu template engine.
package subtpl

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MMWOrg/mmwX-plugins/proxyparser"
	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/sub"
	"gopkg.in/yaml.v3"
)

type Document struct {
	Body        string   `json:"body"`
	ContentType string   `json:"content_type"`
	Client      string   `json:"client"`
	TemplateID  string   `json:"template_id"`
	Warnings    []string `json:"warnings"`
}

func cleanName(name string) string {
	name = strings.TrimSpace(strings.NewReplacer("\r", "_", "\n", "_", ",", "_", "=", "_").Replace(name))
	if name == "" {
		name = "Node"
	}
	if name == "DIRECT" || name == "REJECT" || name == "PROXY" {
		name = "Node " + name
	}
	return name
}

func Proxies(nodes []sub.Node, extra []string) ([]substore.Proxy, []string) {
	proxies := make([]substore.Proxy, 0, len(nodes)+len(extra))
	warnings := []string{}
	for _, n := range nodes {
		kind := strings.ToLower(n.Protocol)
		if kind == "shadowsocks" {
			kind = "ss"
		}
		if kind == "https" {
			kind = "http"
		}
		if kind == "socks5" {
			kind = "socks"
		}
		p := substore.Proxy{"name": n.Name, "type": kind, "server": n.Host, "port": n.Port, "udp": kind != "http"}
		switch kind {
		case "ss":
			p["cipher"], p["password"] = n.Cipher, n.Password
		case "http", "socks":
			if kind == "socks" {
				p["type"] = "socks5"
			}
			if user := strings.TrimSpace(n.Username); user != "" {
				p["username"] = user
			} else if n.UUID != "" {
				p["username"] = n.UUID
			}
			p["password"] = n.Password
		case "trojan", "hysteria2", "anytls":
			p["password"] = n.Password
		case "tuic":
			p["uuid"], p["password"] = n.UUID, n.Password
		default:
			p["uuid"] = n.UUID
		}
		if kind == "vmess" {
			p["cipher"], p["alterId"] = "auto", 0
		}
		if n.Flow != "" {
			p["flow"] = n.Flow
		}
		if n.Type != "" && n.Type != "tcp" && n.Type != "raw" && n.Type != "quic" {
			p["network"] = n.Type
		}
		if n.Security == "tls" || n.Security == "reality" {
			p["tls"] = true
		}
		if n.SNI != "" {
			p["sni"], p["servername"] = n.SNI, n.SNI
		}
		if n.Fingerprint != "" {
			p["client-fingerprint"] = n.Fingerprint
		}
		if n.ALPN != "" {
			p["alpn"] = strings.Split(n.ALPN, ",")
		}
		if n.Security == "reality" {
			p["reality-opts"] = map[string]any{"public-key": n.PublicKey, "short-id": n.ShortID}
		}
		switch n.Type {
		case "ws":
			ws := map[string]any{"path": n.Path}
			if n.HostHeader != "" {
				ws["headers"] = map[string]any{"Host": n.HostHeader}
			}
			p["ws-opts"] = ws
		case "grpc":
			p["grpc-opts"] = map[string]any{"grpc-service-name": n.ServiceName}
		case "httpupgrade":
			p["network"] = "ws"
			p["ws-opts"] = map[string]any{"path": n.Path, "v2ray-http-upgrade": true, "headers": map[string]any{"Host": n.HostHeader}}
		case "xhttp":
			p["xhttp-opts"] = map[string]any{"path": n.Path, "host": n.HostHeader, "mode": n.Mode}
		}
		proxies = append(proxies, p)
	}
	for _, raw := range extra {
		p, err := proxyparser.Parse(raw)
		if err != nil {
			warnings = append(warnings, "An external node could not be parsed")
			continue
		}
		switch fmt.Sprint(p["type"]) {
		case "ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "http", "socks", "socks5":
		default:
			warnings = append(warnings, "An external node uses a protocol outside Lite-Plus subscription support")
			continue
		}
		proxies = append(proxies, substore.Proxy(p))
	}
	used := map[string]bool{}
	for _, p := range proxies {
		base := cleanName(substore.GetString(p, "name"))
		name := base
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		p["name"], used[name] = name, true
	}
	return proxies, warnings
}

// Prepare removes embedded node credentials before saving or rendering a template.
// Remote node subscriptions belong in per-user extra links, not shared templates.
func Prepare(kind, content string) (string, error) {
	if len(content) == 0 || len(content) > 1024*1024 {
		return "", fmt.Errorf("template must be between 1 byte and 1 MiB")
	}
	switch kind {
	case "clash":
		var root map[string]any
		if err := yaml.Unmarshal([]byte(content), &root); err != nil {
			return "", fmt.Errorf("invalid YAML template: %w", err)
		}
		if len(root) == 0 {
			return "", fmt.Errorf("YAML template must be an object")
		}
		if providers, ok := root["proxy-providers"].(map[string]any); ok && len(providers) > 0 {
			return "", fmt.Errorf("put remote node subscriptions in user extra links instead of proxy-providers")
		}
		root["proxies"] = []any{}
		b, err := yaml.Marshal(root)
		return string(b), err
	case "sing-box":
		var root map[string]any
		if err := json.Unmarshal([]byte(content), &root); err != nil {
			return "", fmt.Errorf("invalid JSON template: %w", err)
		}
		if len(root) == 0 {
			return "", fmt.Errorf("JSON template must be an object")
		}
		outbounds, ok := root["outbounds"].([]any)
		if !ok {
			return "", fmt.Errorf("sing-box template requires an outbounds array")
		}
		kept := []any{}
		for _, raw := range outbounds {
			out, ok := raw.(map[string]any)
			if !ok {
				return "", fmt.Errorf("invalid sing-box outbound")
			}
			switch out["type"] {
			case "selector", "urltest", "direct", "block", "dns":
				kept = append(kept, out)
			}
		}
		root["outbounds"] = kept
		delete(root, "endpoints")
		b, err := json.MarshalIndent(root, "", "  ")
		return string(b), err
	case "loon", "surge":
		if !hasSection(content, "Proxy") || !hasSection(content, "Proxy Group") || !hasSection(content, "Rule") {
			return "", fmt.Errorf("native template requires [Proxy], [Proxy Group] and [Rule]")
		}
		if hasSection(content, "Remote Proxy") {
			return "", fmt.Errorf("put remote node subscriptions in user extra links instead of [Remote Proxy]")
		}
		return replaceSections(content, map[string]string{"proxy": "", "proxy chain": ""}), nil
	default:
		return "", fmt.Errorf("unsupported template kind")
	}
}

func hasSection(content, name string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "["+name+"]") {
			return true
		}
	}
	return false
}

func replaceSections(content string, replacements map[string]string) string {
	var out []string
	section := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			out = append(out, line)
			if body, ok := replacements[section]; ok {
				out = append(out, strings.TrimRight(body, "\n"))
				seen[section] = true
			}
			continue
		}
		if _, replace := replacements[section]; !replace {
			out = append(out, line)
		}
	}
	keys := []string{}
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !seen[key] && replacements[key] != "" {
			out = append(out, "", "["+key+"]", replacements[key])
		}
	}
	return strings.Join(out, "\n")
}

func producer(client string) (substore.Producer, error) {
	if client == "mihomo" {
		client = "clashmeta"
	}
	if client == "surge-mac" {
		client = "surgemac"
	}
	// Producers may keep request options in receiver fields. Never share across requests.
	return substore.NewProducerFactory().GetProducer(client)
}

func Render(client string, tpl models.SubscriptionTemplate, nodes []sub.Node, extra []string) (Document, error) {
	doc := Document{Client: client, TemplateID: tpl.ID, Warnings: []string{}}
	prepared, err := Prepare(tpl.Kind, tpl.Content)
	if err != nil {
		return doc, err
	}
	proxies, warnings := Proxies(nodes, extra)
	doc.Warnings = append(doc.Warnings, warnings...)
	prod, err := producer(client)
	if err != nil {
		return doc, err
	}
	filtered := []substore.Proxy{}
	names := []string{}
	for _, p := range proxies {
		outputType := "internal"
		if tpl.Kind == "loon" || tpl.Kind == "surge" {
			outputType = ""
		}
		v, e := prod.Produce([]substore.Proxy{p}, outputType, &substore.ProduceOptions{ClientCompatibilityMode: true})
		// Native producers return text; YAML producers return Proxy slices; sing-box returns JSON.
		supported := e == nil
		switch value := v.(type) {
		case string:
			supported = supported && strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "[]"
		case []substore.Proxy:
			supported = supported && len(value) > 0
		case []map[string]any:
			supported = supported && len(value) > 0
		case nil:
			supported = false
		}
		if !supported {
			features := []string{substore.GetString(p, "type")}
			if network := substore.GetString(p, "network"); network != "" {
				features = append(features, network)
			}
			if substore.IsPresent(p, "reality-opts") {
				features = append(features, "reality")
			}
			doc.Warnings = append(doc.Warnings, fmt.Sprintf("%s: unsupported by %s (%s)", substore.GetString(p, "name"), client, strings.Join(features, "/")))
			continue
		}
		filtered = append(filtered, p)
		names = append(names, substore.GetString(p, "name"))
	}
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	switch tpl.Kind {
	case "clash":
		converted, err := prod.Produce(filtered, "internal", &substore.ProduceOptions{ClientCompatibilityMode: true})
		if err != nil {
			return doc, err
		}
		items, ok := converted.([]substore.Proxy)
		if !ok {
			return doc, fmt.Errorf("unexpected YAML converter result")
		}
		maps := make([]map[string]any, 0, len(items))
		for _, item := range items {
			maps = append(maps, map[string]any(item))
		}
		body, err := substore.NewTemplateV3Processor(nil, nil).ProcessTemplate(prepared, maps)
		if err != nil {
			return doc, err
		}
		var root map[string]any
		if err := yaml.Unmarshal([]byte(body), &root); err != nil {
			return doc, err
		}
		if _, ok := root["proxy-groups"]; !ok {
			root["proxies"] = maps
		}
		if err := validateClashReferences(root); err != nil {
			return doc, err
		}
		b, err := yaml.Marshal(root)
		if err != nil {
			return doc, err
		}
		doc.Body, doc.ContentType = string(b), "text/yaml; charset=utf-8"
	case "loon", "surge":
		sections := map[string]string{}
		if client == "loon" {
			proxyLines, chainLines, err := substore.BuildLoonProxySections(filtered, nativeGroupNames(prepared))
			if err != nil {
				return doc, err
			}
			sections["proxy"], sections["proxy chain"] = proxyLines, chainLines
		} else {
			value, err := prod.Produce(filtered, "", &substore.ProduceOptions{ClientCompatibilityMode: true})
			if err != nil {
				return doc, err
			}
			var ok bool
			sections["proxy"], ok = value.(string)
			if !ok {
				return doc, fmt.Errorf("unexpected native converter result")
			}
		}
		doc.Body = replaceSections(prepared, sections)
		doc.Body = strings.ReplaceAll(doc.Body, "__PROXY_NODES__", strings.Join(names, ", "))
		if err := validateNativeReferences(doc.Body, names); err != nil {
			return doc, err
		}
		doc.ContentType = "text/plain; charset=utf-8"
	case "sing-box":
		value, err := prod.Produce(filtered, "internal", &substore.ProduceOptions{ClientCompatibilityMode: true})
		if err != nil {
			return doc, err
		}
		generated, ok := value.([]map[string]any)
		if !ok {
			return doc, fmt.Errorf("unexpected JSON converter result")
		}
		var root map[string]any
		if err := json.Unmarshal([]byte(prepared), &root); err != nil {
			return doc, err
		}
		outs := root["outbounds"].([]any)
		generatedNames := []any{}
		known := map[string]bool{}
		for _, out := range generated {
			known[fmt.Sprint(out["tag"])] = true
			generatedNames = append(generatedNames, out["tag"])
		}
		for _, raw := range outs {
			out := raw.(map[string]any)
			tag, _ := out["tag"].(string)
			if tag == "" || known[tag] {
				return doc, fmt.Errorf("duplicate or missing outbound tag")
			}
			known[tag] = true
		}
		// Imported templates may name their direct outbound differently from DIRECT.
		fallback := ""
		for _, raw := range outs {
			out := raw.(map[string]any)
			if out["type"] == "direct" {
				fallback = fmt.Sprint(out["tag"])
				break
			}
		}
		for _, raw := range outs {
			out := raw.(map[string]any)
			if refs, ok := out["outbounds"].([]any); ok {
				expanded := []any{}
				for _, ref := range refs {
					if ref == "__PROXY_NODES__" || ref == "{all}" {
						expanded = append(expanded, generatedNames...)
					} else {
						expanded = append(expanded, ref)
					}
				}
				if len(expanded) == 0 {
					if fallback == "" {
						fallback = "DIRECT"
						for n := 2; known[fallback]; n++ {
							fallback = fmt.Sprintf("DIRECT %d", n)
						}
						known[fallback] = true
						outs = append(outs, map[string]any{"type": "direct", "tag": fallback})
					}
					expanded = []any{fallback}
				}
				out["outbounds"] = expanded
			}
		}
		for _, out := range generated {
			outs = append(outs, out)
		}
		for _, raw := range outs {
			out := raw.(map[string]any)
			if refs, ok := out["outbounds"].([]any); ok {
				for _, ref := range refs {
					if !known[fmt.Sprint(ref)] {
						return doc, fmt.Errorf("unknown outbound reference: %s", ref)
					}
				}
			}
		}
		root["outbounds"] = outs
		if route, ok := root["route"].(map[string]any); ok {
			if final, ok := route["final"].(string); ok && !known[final] {
				return doc, fmt.Errorf("unknown final outbound: %s", final)
			}
			if err := validateRouteReferences(route, known); err != nil {
				return doc, err
			}
		}
		b, err := json.MarshalIndent(root, "", "  ")
		if err != nil {
			return doc, err
		}
		doc.Body, doc.ContentType = string(b), "application/json; charset=utf-8"
	}
	return doc, nil
}

func nativeGroupNames(content string) []string {
	section := ""
	names := []string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if section == "[proxy group]" && !strings.HasPrefix(t, "#") {
			if i := strings.Index(t, "="); i > 0 {
				names = append(names, strings.TrimSpace(t[:i]))
			}
		}
	}
	return names
}

func validateClashReferences(root map[string]any) error {
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}
	for _, key := range []string{"proxies", "proxy-groups"} {
		if list, ok := root[key].([]any); ok {
			for _, raw := range list {
				if row, ok := raw.(map[string]any); ok {
					name, _ := row["name"].(string)
					if name == "" || known[name] {
						return fmt.Errorf("duplicate or missing proxy/group name")
					}
					known[name] = true
				}
			}
		}
	}
	if groups, ok := root["proxy-groups"].([]any); ok {
		for _, raw := range groups {
			group, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid proxy group")
			}
			if refs, ok := group["proxies"].([]any); ok {
				for _, ref := range refs {
					if !known[fmt.Sprint(ref)] {
						return fmt.Errorf("unknown proxy reference: %s", ref)
					}
				}
			}
		}
	}
	if rules, ok := root["rules"].([]any); ok {
		for _, raw := range rules {
			if rule, ok := raw.(string); ok && !strings.HasPrefix(strings.ToUpper(rule), "SUB-RULE,") {
				if policy := rulePolicy(rule); policy != "" && !known[policy] {
					return fmt.Errorf("unknown rule policy: %s", policy)
				}
			}
		}
	}
	return nil
}

func rulePolicy(rule string) string {
	parts := strings.Split(rule, ",")
	if len(parts) < 2 {
		return ""
	}
	i := len(parts) - 1
	if strings.EqualFold(strings.TrimSpace(parts[i]), "no-resolve") {
		i--
	}
	return strings.TrimSpace(parts[i])
}

func validateRouteReferences(route map[string]any, known map[string]bool) error {
	if outbound, ok := route["outbound"].(string); ok && !known[outbound] {
		return fmt.Errorf("unknown route outbound: %s", outbound)
	}
	if rules, ok := route["rules"].([]any); ok {
		for _, raw := range rules {
			if rule, ok := raw.(map[string]any); ok {
				if err := validateRouteReferences(rule, known); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateNativeReferences(body string, nodes []string) error {
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "REJECT-TINYGIF": true, "REJECT-NO-DROP": true}
	for _, name := range nodes {
		known[name] = true
	}
	for _, name := range nativeGroupNames(body) {
		known[name] = true
	}
	section := ""
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if section == "[proxy group]" {
			i := strings.Index(t, "=")
			if i < 0 {
				continue
			}
			args := splitNativeArgs(t[i+1:])
			if len(args) == 0 {
				continue
			}
			switch strings.ToLower(args[0]) {
			case "select", "url-test", "fallback", "load-balance":
			default:
				continue
			}
			for _, arg := range args[1:] {
				if arg == "" || strings.Contains(arg, "=") {
					continue
				}
				if !known[arg] {
					return fmt.Errorf("unknown native policy reference: %s", arg)
				}
			}
		}
		if section == "[rule]" {
			if policy := rulePolicy(t); policy != "" && !known[policy] {
				return fmt.Errorf("unknown rule policy: %s", policy)
			}
		}
	}
	return nil
}

func splitNativeArgs(raw string) []string {
	args := []string{}
	start := 0
	var quote rune
	escaped := false
	for i, r := range raw {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ',' {
			args = append(args, strings.Trim(strings.TrimSpace(raw[start:i]), "\"'"))
			start = i + 1
		}
	}
	return append(args, strings.Trim(strings.TrimSpace(raw[start:]), "\"'"))
}
