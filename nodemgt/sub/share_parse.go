package sub

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func mergeExtraNodes(nodes []Node, extra []string) ([]Node, []string) {
	out := append([]Node(nil), nodes...)
	var rest []string
	for _, line := range extra {
		n, ok := NodeFromShareLink(line)
		if !ok {
			if strings.TrimSpace(line) != "" {
				rest = append(rest, line)
			}
			continue
		}
		out = append(out, n)
	}
	return out, rest
}

func NodeFromShareLink(raw string) (Node, bool) {
	line := strings.TrimSpace(raw)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		line = line[:i]
	}
	if !strings.Contains(line, "://") {
		return Node{}, false
	}
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVmessShare(line)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocksShare(line)
	default:
		return parseURIShare(line)
	}
}

func parseURIShare(raw string) (Node, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return Node{}, false
	}
	protocol := strings.ToLower(u.Scheme)
	switch protocol {
	case "hy2":
		protocol = "hysteria2"
	case "https":
		protocol = "http"
	case "socks5":
		protocol = "socks"
	case "vless", "trojan", "anytls", "hysteria2", "tuic", "http", "socks":
	default:
		return Node{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Node{}, false
	}
	port := 443
	if protocol == "http" || protocol == "socks" {
		port = 80
	}
	if strings.EqualFold(u.Scheme, "https") {
		port = 443
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return Node{}, false
		}
		port = p
	}
	q := u.Query()
	transport := strings.ToLower(firstQuery(q, "type", "net", "network"))
	if transport == "" {
		transport = "tcp"
	}
	if transport == "websocket" {
		transport = "ws"
	}
	security := strings.ToLower(firstQuery(q, "security", "tls"))
	switch security {
	case "":
		switch protocol {
		case "vless", "http", "socks":
			if strings.EqualFold(u.Scheme, "https") {
				security = "tls"
			} else {
				security = "none"
			}
		default:
			security = "tls"
		}
	case "1", "true":
		security = "tls"
	}
	name := strings.TrimSpace(u.Fragment)
	if name == "" {
		name = host
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	n := Node{
		Name:        name,
		Protocol:    protocol,
		Host:        host,
		Port:        port,
		Security:    security,
		Type:        transport,
		Path:        firstQuery(q, "path"),
		HostHeader:  firstQuery(q, "host", "authority"),
		SNI:         firstQuery(q, "sni", "servername", "peer"),
		Flow:        firstQuery(q, "flow"),
		Fingerprint: firstQuery(q, "fp", "fingerprint"),
		PublicKey:   firstQuery(q, "pbk", "publickey"),
		ShortID:     firstQuery(q, "sid", "shortid"),
		SpiderX:     firstQuery(q, "spx", "spiderx"),
		ServiceName: firstQuery(q, "servicename", "service"),
		ALPN:        firstQuery(q, "alpn"),
		Mode:        firstQuery(q, "mode"),
	}
	switch protocol {
	case "vless":
		n.UUID = user
	case "tuic":
		n.UUID = user
		n.Password = pass
	case "http", "socks":
		n.Username = user
		n.UUID = user
		n.Password = pass
		if n.Password == "" {
			n.Password = user
		}
	default:
		n.Password = user
		if n.Password == "" {
			n.Password = pass
		}
	}
	if n.UUID == "" && n.Password == "" {
		return Node{}, false
	}
	return n, true
}

func parseVmessShare(raw string) (Node, bool) {
	payload := decodeShareBase64(strings.TrimPrefix(raw, "vmess://"))
	if payload == "" {
		return Node{}, false
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return Node{}, false
	}
	str := func(keys ...string) string {
		for _, key := range keys {
			if v, ok := data[key]; ok {
				switch t := v.(type) {
				case string:
					if s := strings.TrimSpace(t); s != "" {
						return s
					}
				case float64:
					return strconv.FormatInt(int64(t), 10)
				case json.Number:
					return t.String()
				}
			}
		}
		return ""
	}
	host := str("add")
	port, err := strconv.Atoi(str("port"))
	if host == "" || err != nil || port <= 0 || port > 65535 {
		return Node{}, false
	}
	net := strings.ToLower(str("net", "type"))
	if net == "" {
		net = "tcp"
	}
	if net == "websocket" {
		net = "ws"
	}
	security := strings.ToLower(str("tls", "security"))
	if security == "" {
		security = "none"
	}
	name := str("ps")
	if name == "" {
		name = host
	}
	n := Node{
		Name:        name,
		Protocol:    "vmess",
		Host:        host,
		Port:        port,
		UUID:        str("id"),
		Type:        net,
		Security:    security,
		SNI:         str("sni", "host"),
		Fingerprint: str("fp"),
		Path:        str("path"),
		HostHeader:  str("host"),
	}
	if n.UUID == "" {
		return Node{}, false
	}
	if net == "grpc" && n.ServiceName == "" {
		n.ServiceName = str("path")
	}
	return n, true
}

func parseShadowsocksShare(raw string) (Node, bool) {
	rest := strings.TrimPrefix(raw, "ss://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name = decodeURIComponent(rest[i+1:])
		rest = rest[:i]
	}
	var method, password, hostPort string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		user := decodeURIComponent(rest[:at])
		hostPort = rest[at+1:]
		decoded := user
		if !strings.Contains(user, ":") {
			decoded = decodeShareBase64(user)
		}
		split := strings.Index(decoded, ":")
		if split < 0 {
			return Node{}, false
		}
		method, password = decoded[:split], decoded[split+1:]
	} else {
		decoded := decodeShareBase64(rest)
		split := strings.LastIndex(decoded, "@")
		if split < 0 {
			return Node{}, false
		}
		user, hp := decoded[:split], decoded[split+1:]
		hostPort = hp
		colon := strings.Index(user, ":")
		if colon < 0 {
			return Node{}, false
		}
		method, password = user[:colon], user[colon+1:]
	}
	host, port, ok := splitShareHostPort(hostPort)
	if !ok || password == "" {
		return Node{}, false
	}
	if name == "" {
		name = host
	}
	return Node{
		Name:     name,
		Protocol: "shadowsocks",
		Host:     host,
		Port:     port,
		Password: password,
		Cipher:   method,
		Type:     "tcp",
		Security: "none",
	}, true
}

func splitShareHostPort(hostPort string) (string, int, bool) {
	hostPort = strings.TrimSpace(hostPort)
	if host, portStr, err := net.SplitHostPort(hostPort); err == nil {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, false
		}
		return host, port, true
	}
	colon := strings.LastIndex(hostPort, ":")
	if colon < 1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(hostPort[colon+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	host := strings.TrimSuffix(strings.TrimPrefix(hostPort[:colon], "["), "]")
	if host == "" {
		return "", 0, false
	}
	return host, port, true
}

func firstQuery(q url.Values, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

func decodeURIComponent(raw string) string {
	if raw == "" {
		return ""
	}
	if dec, err := url.PathUnescape(raw); err == nil {
		return dec
	}
	if dec, err := url.QueryUnescape(raw); err == nil {
		return dec
	}
	return raw
}

func decodeShareBase64(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(raw); err == nil {
			return string(b)
		}
	}
	return ""
}
