package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

func FileKey(domain string) string {
	d := strings.TrimPrefix(NormalizeDomain(domain), "*.")
	d = strings.ReplaceAll(d, "*", "_")
	if d == "" {
		return "cert"
	}
	return d
}

func ApexOf(domain string) string {
	return strings.TrimPrefix(NormalizeDomain(domain), "*.")
}

func DefaultCoverWildcard(domain string) bool {
	d := NormalizeDomain(domain)
	if d == "" {
		return false
	}
	if strings.HasPrefix(d, "*.") {
		return true
	}
	return strings.Count(d, ".") == 1
}

func IssueNames(domain string, coverWildcard bool) []string {
	d := NormalizeDomain(domain)
	if d == "" {
		return nil
	}
	if strings.HasPrefix(d, "*.") {
		apex := strings.TrimPrefix(d, "*.")
		if apex == "" {
			return nil
		}
		return uniqueNames(apex, "*."+apex)
	}
	if coverWildcard {
		return uniqueNames(d, "*."+d)
	}
	return []string{d}
}

func CommonName(names []string) string {
	for _, n := range uniqueNames(names...) {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	if len(names) == 0 {
		return ""
	}
	return ApexOf(names[0])
}

func ChallengeHost(domain string) string {
	return "_acme-challenge." + ApexOf(domain)
}

func RootDomain(domain string) string {
	return ApexOf(domain)
}

func HostCovered(root, host string) bool {
	root = RootDomain(root)
	host = NormalizeDomain(host)
	if root == "" || host == "" {
		return false
	}
	if host == root {
		return true
	}
	suffix := "." + root
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	rest := strings.TrimSuffix(host, suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

func UsableShareHost(domain, shareDomain string) string {
	if s := NormalizeDomain(shareDomain); s != "" && !strings.HasPrefix(s, "*.") {
		return s
	}
	d := NormalizeDomain(domain)
	if strings.HasPrefix(d, "*.") {
		return strings.TrimPrefix(d, "*.")
	}
	return d
}

func uniqueNames(names ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = NormalizeDomain(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func nameSetEqual(got, want []string) bool {
	left := uniqueNames(got...)
	right := uniqueNames(want...)
	if len(left) != len(right) {
		return false
	}
	seen := map[string]struct{}{}
	for _, n := range left {
		seen[n] = struct{}{}
	}
	for _, n := range right {
		if _, ok := seen[n]; !ok {
			return false
		}
	}
	return true
}

func cnAllowed(cn string, want []string) bool {
	cn = NormalizeDomain(cn)
	if cn == "" {
		return true
	}
	for _, n := range uniqueNames(want...) {
		if n == cn {
			return true
		}
		if strings.HasPrefix(n, "*.") && ApexOf(n) == cn {
			return true
		}
	}
	return false
}

func CSRNamesMatch(csrPEM string, names []string) error {
	want := uniqueNames(names...)
	if len(want) == 0 {
		return fmt.Errorf("domain required")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	if !cnAllowed(csr.Subject.CommonName, want) {
		return fmt.Errorf("csr cn")
	}
	got := csr.DNSNames
	if len(got) == 0 && strings.TrimSpace(csr.Subject.CommonName) != "" {
		got = []string{csr.Subject.CommonName}
	}
	if !nameSetEqual(got, want) {
		return fmt.Errorf("csr san")
	}
	return nil
}
