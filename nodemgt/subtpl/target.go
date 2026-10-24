package subtpl

import (
	"fmt"
	"strings"
)

type Selection struct {
	Client       string
	LegacyFormat string
}

func NormalizeClient(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mihomo", "clashmeta", "clash-meta":
		return "mihomo", nil
	case "clash":
		return "clash", nil
	case "loon":
		return "loon", nil
	case "surge":
		return "surge", nil
	case "surge-mac", "surgemac":
		return "surge-mac", nil
	case "stash":
		return "stash", nil
	case "sing-box", "singbox":
		return "sing-box", nil
	case "xray", "v2ray", "v2rayn", "base64", "shadowrocket":
		return "v2ray", nil
	}
	return "", fmt.Errorf("unsupported subscription client")
}

func DetectClient(ua string) string {
	u := strings.ToLower(ua)
	// More specific families precede generic Clash and Surge strings.
	for _, rule := range []struct {
		client  string
		markers []string
	}{
		{"loon", []string{"loon/", "loon "}},
		{"surge-mac", []string{"surge mac", "surgemac", "surge-mac"}},
		{"surge", []string{"surge/", "surge "}},
		{"stash", []string{"stash/", "stash "}},
		{"sing-box", []string{"sing-box", "singbox"}},
		{"v2ray", []string{"shadowrocket", "v2ray", "happ/"}},
		{"mihomo", []string{"mihomo", "clash.meta", "clashmeta", "clash-verge", "clash verge"}},
		{"clash", []string{"clash/", "clash "}},
	} {
		for _, marker := range rule.markers {
			if strings.Contains(u, marker) || strings.TrimSpace(u) == strings.TrimRight(marker, "/ ") {
				return rule.client
			}
		}
	}
	return ""
}

// Legacy formats keep their existing bytes unless a template has explicitly been bound.
func ResolveTarget(target, format, ua, fallback string, auto bool) (Selection, error) {
	if strings.TrimSpace(target) != "" {
		client, err := NormalizeClient(target)
		return Selection{Client: client}, err
	}
	if strings.TrimSpace(format) == "" && auto {
		if client := DetectClient(ua); client != "" {
			return Selection{Client: client}, nil
		}
	}
	if format == "" {
		format = fallback
	}
	if format == "" {
		format = "xray"
	}
	client, err := NormalizeClient(format)
	if err != nil {
		return Selection{}, err
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "xray", "v2ray", "v2rayn", "base64", "clash", "sing-box", "singbox":
		return Selection{Client: client, LegacyFormat: format}, nil
	}
	return Selection{Client: client}, nil
}
