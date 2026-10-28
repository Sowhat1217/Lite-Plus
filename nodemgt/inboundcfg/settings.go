package inboundcfg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Settings struct {
	Stack              string `json:"stack,omitempty"`
	PublicHost         string `json:"public_host,omitempty"`
	PublicPort         int    `json:"public_port,omitempty"`
	Flow               string `json:"flow,omitempty"`
	Transport          string `json:"transport,omitempty"`
	Security           string `json:"security,omitempty"`
	SNI                string `json:"sni,omitempty"`
	TLSDomain          string `json:"tls_domain,omitempty"`
	ALPN               string `json:"alpn,omitempty"`
	CertID             string `json:"cert_id,omitempty"`
	RealityDest        string `json:"reality_dest,omitempty"`
	RealityServerNames string `json:"reality_server_names,omitempty"`
	RealityPrivateKey  string `json:"reality_private_key,omitempty"`
	RealityShortID     string `json:"reality_short_id,omitempty"`
	RealityPublicKey   string `json:"reality_public_key,omitempty"`
	WSPath             string `json:"ws_path,omitempty"`
	WSHost             string `json:"ws_host,omitempty"`
	GRPCService        string `json:"grpc_service,omitempty"`
	GRPCMulti          bool   `json:"grpc_multi,omitempty"`
	HTTPPath           string `json:"http_path,omitempty"`
	HTTPHost           string `json:"http_host,omitempty"`
	HTTPMode           string `json:"http_mode,omitempty"`
	TCPHeader          string `json:"tcp_header,omitempty"`
	TCPHost            string `json:"tcp_host,omitempty"`
	SSMethod           string `json:"ss_method,omitempty"`
	SSPassword         string `json:"ss_password,omitempty"`
	SSNetwork          string `json:"ss_network,omitempty"`
	UDPFragment        *bool  `json:"udp_fragment,omitempty"`
	Accounts           []ProxyAccount `json:"accounts,omitempty"`
	AllowTransparent   bool           `json:"allow_transparent,omitempty"`
	Fingerprint        string `json:"fingerprint,omitempty"`
	SpiderX            string `json:"spider_x,omitempty"`
	Sniffing           bool   `json:"sniffing,omitempty"`
	DestOverride       string `json:"dest_override,omitempty"`
	RouteOnly          bool   `json:"route_only,omitempty"`
	ExcludeFromSub     bool   `json:"exclude_from_sub,omitempty"`
	ShareStrategy      string `json:"share_strategy,omitempty"`
}

type ProxyAccount struct {
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

func NormalizeAccounts(rows []ProxyAccount) []ProxyAccount {
	out := make([]ProxyAccount, 0, len(rows))
	seen := map[string]struct{}{}
	for _, row := range rows {
		user := strings.TrimSpace(row.User)
		pass := strings.TrimSpace(row.Pass)
		if user == "" || pass == "" {
			continue
		}
		if _, ok := seen[user]; ok {
			continue
		}
		seen[user] = struct{}{}
		out = append(out, ProxyAccount{User: user, Pass: pass})
	}
	return out
}

func RandomProxyAccount() ProxyAccount {
	return ProxyAccount{User: randomProxyToken(8), Pass: randomProxyToken(12)}
}

func randomProxyToken(n int) string {
	const alphabet = "abcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("x", n)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

func GenerateRealityKeys() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		nil
}

func DestHost(dest string) string {
	host, _, found := strings.Cut(strings.TrimSpace(dest), ":")
	if found {
		return host
	}
	return strings.TrimSpace(dest)
}

// ShareSNI is the name clients should send. Reality uses the dest / server
// names, not a leftover TLS SNI from a previous protocol such as Hysteria2.
func ShareSNI(s Settings) string {
	if strings.EqualFold(strings.TrimSpace(s.Security), "reality") {
		if name := firstCSV(s.RealityServerNames); name != "" {
			return name
		}
		if host := DestHost(s.RealityDest); host != "" {
			return host
		}
	}
	if name := strings.TrimSpace(s.SNI); name != "" {
		return name
	}
	return strings.TrimSpace(s.TLSDomain)
}

func NormalizeShareStrategy(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "listen":
		return "listen"
	case "other", "specified":
		return "other"
	case "none":
		return "none"
	default:
		return "node"
	}
}

func Parse(raw string) Settings {
	var s Settings
	if strings.TrimSpace(raw) == "" {
		return s
	}
	_ = json.Unmarshal([]byte(raw), &s)
	return s
}

func (s Settings) Marshal() string {
	b, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func ListenForStack(stack, listen string) string {
	listen = strings.TrimSpace(listen)
	if listen != "" && !IsWildcardListen(listen) {
		return listen
	}
	hosts := FrontListenHosts(stack, listen)
	return strings.Join(hosts, ",")
}

func IsWildcardListen(listen string) bool {
	switch strings.ToLower(strings.TrimSpace(listen)) {
	case "", "*", "0.0.0.0", "::", "[::]", "0.0.0.0,::", "::,0.0.0.0":
		return true
	default:
		return false
	}
}

func FrontListenHosts(stack, listen string) []string {
	listen = strings.TrimSpace(listen)
	if listen != "" && !IsWildcardListen(listen) {
		return []string{unwrapListenHost(listen)}
	}
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv4":
		return []string{"0.0.0.0"}
	case "ipv6":
		return []string{"::"}
	default:
		return []string{"0.0.0.0", "::"}
	}
}

func unwrapListenHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) > 2 {
		return host[1 : len(host)-1]
	}
	return host
}

func DefaultCore(protocol string) string {
	switch strings.ToLower(protocol) {
	case "hysteria2", "tuic", "anytls":
		return "sing-box"
	default:
		return "xray"
	}
}

func DefaultTransport(protocol string) string {
	switch strings.ToLower(protocol) {
	case "hysteria2", "tuic":
		return "quic"
	case "shadowsocks":
		return "tcp,udp"
	default:
		return "tcp"
	}
}

func NormalizeSSNetwork(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "/", ",")
	s = strings.ReplaceAll(s, "+", ",")
	switch s {
	case "udp":
		return "udp"
	case "tcp":
		return "tcp"
	default:
		return "tcp,udp"
	}
}

func InboundListensUDP(protocol string, s Settings) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic":
		return true
	case "shadowsocks":
		return EffectiveSSNetwork(s) != "tcp"
	default:
		return false
	}
}

func EffectiveUDPFragment(protocol string, s Settings) bool {
	if s.UDPFragment != nil {
		return *s.UDPFragment
	}
	return false
}

func EffectiveSSNetwork(s Settings) string {
	if n := strings.TrimSpace(s.SSNetwork); n != "" {
		return NormalizeSSNetwork(n)
	}
	t := strings.ToLower(strings.TrimSpace(s.Transport))
	t = strings.ReplaceAll(t, " ", "")
	switch t {
	case "udp", "tcp,udp", "tcp+udp", "tcp/udp", "tcpudp":
		return NormalizeSSNetwork(t)
	default:
		return "tcp,udp"
	}
}

func DefaultSecurity(protocol string) string {
	switch strings.ToLower(protocol) {
	case "trojan", "hysteria2", "tuic", "anytls":
		return "tls"
	default:
		return ""
	}
}

func DefaultDestOverride() string {
	return "http,tls,quic"
}

func ForceSniffRouteOnly(s Settings) bool {
	if !s.Sniffing {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(s.Security), "reality") {
		return true
	}
	return strings.Contains(strings.ToLower(s.Flow), "vision")
}

func EffectiveRouteOnly(s Settings) bool {
	if !s.Sniffing {
		return false
	}
	if ForceSniffRouteOnly(s) {
		return true
	}
	return s.RouteOnly
}

func NormalizeSniffSettingsJSON(raw string) string {
	s := Parse(raw)
	if !s.Sniffing {
		return raw
	}
	want := EffectiveRouteOnly(s)
	if s.RouteOnly == want {
		return raw
	}
	s.RouteOnly = want
	return s.Marshal()
}

func StreamJSON(s Settings, protocol string) string {
	transport := s.Transport
	if transport == "" {
		transport = DefaultTransport(protocol)
	}
	security := s.Security
	if security == "" {
		security = DefaultSecurity(protocol)
	}
	if strings.EqualFold(protocol, "http") || strings.EqualFold(protocol, "shadowsocks") {
		transport = "tcp"
		if strings.EqualFold(security, "reality") {
			security = "none"
		}
	}
	stream := map[string]any{
		"network":  transport,
		"security": security,
		"stack":    s.Stack,
	}
	if security == "tls" {
		tls := map[string]any{}
		if s.SNI != "" {
			tls["serverName"] = s.SNI
		} else if s.TLSDomain != "" {
			tls["serverName"] = s.TLSDomain
		}
		if s.ALPN != "" {
			tls["alpn"] = splitCSV(s.ALPN)
		}
		if s.Fingerprint != "" {
			tls["fingerprint"] = s.Fingerprint
		}
		stream["tlsSettings"] = tls
	}
	if security == "reality" {
		dest := s.RealityDest
		reality := map[string]any{
			"dest":        dest,
			"target":      dest,
			"serverNames": splitCSV(s.RealityServerNames),
			"shortIds":    splitCSV(s.RealityShortID),
		}
		if s.Fingerprint != "" {
			reality["fingerprint"] = s.Fingerprint
		}
		if s.SpiderX != "" {
			reality["spiderX"] = s.SpiderX
		}
		if s.RealityPrivateKey != "" {
			reality["privateKey"] = s.RealityPrivateKey
		}
		settings := map[string]any{}
		if s.RealityPublicKey != "" {
			settings["publicKey"] = s.RealityPublicKey
		}
		if s.Fingerprint != "" {
			settings["fingerprint"] = s.Fingerprint
		}
		if s.SpiderX != "" {
			settings["spiderX"] = s.SpiderX
		}
		if name := firstCSV(s.RealityServerNames); name != "" {
			settings["serverName"] = name
		}
		if len(settings) > 0 {
			reality["settings"] = settings
		}
		stream["realitySettings"] = reality
	}
	switch transport {
	case "ws":
		path := s.WSPath
		if path == "" {
			path = "/"
		}
		ws := map[string]any{"path": path}
		if s.WSHost != "" {
			ws["host"] = s.WSHost
			ws["headers"] = map[string]any{"Host": s.WSHost}
		}
		stream["wsSettings"] = ws
	case "grpc":
		svc := s.GRPCService
		if svc == "" {
			svc = "gun"
		}
		stream["grpcSettings"] = map[string]any{"serviceName": svc, "multiMode": s.GRPCMulti}
	case "xhttp":
		path := s.HTTPPath
		if path == "" {
			path = "/"
		}
		mode := s.HTTPMode
		if mode == "" {
			mode = "auto"
		}
		xhttp := map[string]any{"path": path, "mode": mode}
		if s.HTTPHost != "" {
			xhttp["host"] = s.HTTPHost
		}
		stream["xhttpSettings"] = xhttp
	case "httpupgrade":
		path := s.HTTPPath
		if path == "" {
			path = s.WSPath
		}
		if path == "" {
			path = "/"
		}
		up := map[string]any{"path": path}
		host := s.HTTPHost
		if host == "" {
			host = s.WSHost
		}
		if host != "" {
			up["host"] = host
		}
		stream["httpupgradeSettings"] = up
	case "tcp":
		if s.TCPHeader == "http" && !strings.EqualFold(protocol, "shadowsocks") && !strings.EqualFold(protocol, "http") {
			host := s.TCPHost
			if host == "" {
				host = s.SNI
			}
			if host == "" {
				host = DestHost(s.RealityDest)
			}
			path := s.HTTPPath
			if path == "" {
				path = "/"
			}
			header := map[string]any{"type": "http"}
			if host != "" {
				header["request"] = map[string]any{
					"path":    []string{path},
					"headers": map[string]any{"Host": []string{host}},
				}
			}
			stream["tcpSettings"] = map[string]any{"header": header}
		}
	}
	b, err := json.Marshal(stream)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func SniffingJSON(s Settings) map[string]any {
	if !s.Sniffing {
		return nil
	}
	dest := splitCSV(s.DestOverride)
	if len(dest) == 0 {
		dest = splitCSV(DefaultDestOverride())
	}
	return map[string]any{
		"enabled":      true,
		"destOverride": dest,
		"routeOnly":    EffectiveRouteOnly(s),
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstCSV(raw string) string {
	parts := splitCSV(raw)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
