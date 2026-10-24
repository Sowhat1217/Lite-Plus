package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
)

const (
	extraFetchTimeout = 6 * time.Second
	extraFetchMaxBody = 2 << 20
	extraFetchCache   = 5 * time.Minute
)

type FetchStatus struct {
	ID  string
	At  time.Time
	Err string
}

type extraCacheEntry struct {
	until time.Time
	links []string
}

var extraCache = struct {
	mu    sync.Mutex
	items map[string]extraCacheEntry
}{items: map[string]extraCacheEntry{}}

var extraHTTPClient = &http.Client{
	Timeout: extraFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if err := guardFetchURL(req.URL); err != nil {
			return err
		}
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

func ExpandExtras(links []models.UserExtraLink, extraURLs string, at time.Time) ([]string, []FetchStatus) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var out []string
	var status []FetchStatus
	for _, row := range links {
		if !row.Enabled {
			continue
		}
		if row.ExpiresAt != nil && !row.ExpiresAt.After(at) {
			continue
		}
		value := strings.TrimSpace(row.Value)
		if value == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(row.Kind))
		if kind == models.ExtraLinkKindSubscription || looksLikeHTTP(value) && kind != models.ExtraLinkKindLink {
			fetched, fetchErr := fetchRemoteShareLinks(value)
			status = append(status, FetchStatus{ID: row.ID, At: at, Err: fetchErr})
			for _, link := range fetched {
				out = append(out, applyNamePrefix(applyRemarkToLink(link, ""), row.NamePrefix))
			}
			continue
		}
		out = append(out, applyRemarkToLink(value, row.Remark))
	}
	for _, line := range ParseExtraURLs(extraURLs) {
		if looksLikeHTTP(line) {
			fetched, _ := fetchRemoteShareLinks(line)
			out = append(out, fetched...)
			continue
		}
		out = append(out, line)
	}
	return out, status
}

func looksLikeHTTP(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func guardFetchURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("empty url")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("empty host")
	}
	return nil
}

func fetchRemoteShareLinks(raw string) ([]string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err.Error()
	}
	if err := guardFetchURL(u); err != nil {
		return nil, err.Error()
	}
	key := u.String()
	extraCache.mu.Lock()
	if hit, ok := extraCache.items[key]; ok && time.Now().Before(hit.until) {
		links := append([]string(nil), hit.links...)
		extraCache.mu.Unlock()
		return links, ""
	}
	extraCache.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, key, nil)
	if err != nil {
		return nil, err.Error()
	}
	req.Header.Set("User-Agent", "Lite-Plus")
	resp, err := extraHTTPClient.Do(req)
	if err != nil {
		return cachedOrError(key, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cachedOrError(key, fmt.Sprintf("status %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, extraFetchMaxBody+1))
	if err != nil {
		return cachedOrError(key, err.Error())
	}
	if len(body) > extraFetchMaxBody {
		return cachedOrError(key, "response too large")
	}
	links := DecodeShareLinks(string(body))
	if len(links) == 0 {
		text := strings.TrimSpace(string(body))
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			links = DecodeShareLinks(string(decoded))
		}
	}
	extraCache.mu.Lock()
	extraCache.items[key] = extraCacheEntry{until: time.Now().Add(extraFetchCache), links: append([]string(nil), links...)}
	extraCache.mu.Unlock()
	return links, ""
}

func cachedOrError(key, errMsg string) ([]string, string) {
	extraCache.mu.Lock()
	defer extraCache.mu.Unlock()
	if hit, ok := extraCache.items[key]; ok {
		return append([]string(nil), hit.links...), errMsg
	}
	return nil, errMsg
}

func applyRemarkToLink(link, remark string) string {
	link = strings.TrimSpace(link)
	remark = strings.TrimSpace(remark)
	if link == "" || remark == "" {
		return link
	}
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return applyVmessName(link, func(name string) string { return remark })
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	u.Fragment = remark
	return u.String()
}

func applyNamePrefix(link, prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return link
	}
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return applyVmessName(link, func(name string) string { return prefix + name })
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	u.Fragment = prefix + u.Fragment
	return u.String()
}

func applyVmessName(link string, next func(string) string) string {
	raw := strings.TrimSpace(strings.TrimPrefix(link, "vmess://"))
	if raw == "" {
		return link
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(raw); err != nil {
				return link
			}
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return link
	}
	name, _ := obj["ps"].(string)
	obj["ps"] = next(name)
	out, err := json.Marshal(obj)
	if err != nil {
		return link
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(out)
}
