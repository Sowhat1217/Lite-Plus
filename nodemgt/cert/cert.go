package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const DefaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"

var (
	cfAPIBase = "https://api.cloudflare.com/client/v4"
	txtSettle = 2 * time.Second
	txtPoll   = 3 * time.Second
)

var lookupTXT = func(ctx context.Context, host string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	return resolver.LookupTXT(ctx, host)
}

type Cloudflare struct {
	APIToken string
	ZoneID   string
	ZoneName string
}

type Request struct {
	Domain        string
	Names         []string
	CoverWildcard bool
	Email         string
	Directory     string
	CSRPEM        string
	CF            Cloudflare
}

func (req Request) issueNames() []string {
	if len(req.Names) > 0 {
		return uniqueNames(req.Names...)
	}
	return IssueNames(req.Domain, req.CoverWildcard)
}

type Result struct {
	ChainPEM    string
	Fingerprint string
	NotAfter    time.Time
	Issuer      string
}

func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func ParseCSR(pemBytes string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func GenerateKeyAndCSR(names []string) (keyPEM, csrPEM string, err error) {
	names = uniqueNames(names...)
	if len(names) == 0 {
		return "", "", fmt.Errorf("domain required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: CommonName(names)},
		DNSNames: names,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", "", err
	}
	return string(keyPEMBytes), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

type RootIssue struct {
	Domain    string
	Email     string
	Directory string
	CF        Cloudflare
	TestCA    bool
}

func IssueRoot(ctx context.Context, req RootIssue) (keyPEM string, issued *Result, err error) {
	domain := RootDomain(req.Domain)
	if domain == "" {
		return "", nil, fmt.Errorf("domain required")
	}
	names := IssueNames(domain, true)
	keyPEM, csrPEM, err := GenerateKeyAndCSR(names)
	if err != nil {
		return "", nil, err
	}
	if req.TestCA {
		issued, err = IssueLocalTestCA(domain, csrPEM)
		return keyPEM, issued, err
	}
	issued, err = IssueACME(ctx, Request{
		Domain:        domain,
		Names:         names,
		CoverWildcard: true,
		Email:         req.Email,
		Directory:     req.Directory,
		CSRPEM:        csrPEM,
		CF:            req.CF,
	})
	return keyPEM, issued, err
}

func IssueLocalTestCA(domain string, csrPEM string) (*Result, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lite-Plus Test CA"},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	dnsNames := uniqueNames(csr.DNSNames...)
	if len(dnsNames) == 0 {
		dnsNames = IssueNames(domain, false)
	}
	cn := strings.TrimSpace(csr.Subject.CommonName)
	if cn == "" {
		cn = CommonName(dnsNames)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().UTC().Add(-time.Minute),
		NotAfter:     time.Now().UTC().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return &Result{
		ChainPEM:    buf.String(),
		Fingerprint: FingerprintSHA256(leafDER),
		NotAfter:    leafTmpl.NotAfter,
		Issuer:      "lite-nodemgt-test-ca",
	}, nil
}

func IssueACME(ctx context.Context, req Request) (*Result, error) {
	if strings.TrimSpace(req.CSRPEM) == "" {
		return nil, fmt.Errorf("csr required; private key stays on the agent")
	}
	if strings.TrimSpace(req.CF.APIToken) == "" {
		return nil, fmt.Errorf("cloudflare api token missing")
	}
	acct, err := acmeAccount(req.Email)
	if err != nil {
		return nil, err
	}
	csr, err := ParseCSR(req.CSRPEM)
	if err != nil {
		return nil, err
	}
	names := req.issueNames()
	if len(names) == 0 {
		return nil, fmt.Errorf("domain required")
	}
	zoneID, zoneName, err := resolveZone(ctx, req.CF.APIToken, ApexOf(names[0]))
	if err != nil {
		return nil, err
	}
	cf := req.CF
	cf.ZoneID = zoneID
	cf.ZoneName = zoneName
	dir := req.Directory
	if dir == "" {
		dir = DefaultDirectory
	}
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: dir}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !isAlreadyReg(err) {
		return nil, fmt.Errorf("acme register: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	pending := make([]pendingChal, 0, len(order.AuthzURLs))
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		ident := NormalizeDomain(authz.Identifier.Value)
		if ident == "" {
			ident = names[0]
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("no dns-01 challenge")
		}
		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		pending = append(pending, pendingChal{
			chal:  chal,
			authz: authz,
			fqdn:  challengeFQDN(ident),
			name:  txtRecordName(ident, cf.ZoneName),
			val:   val,
		})
	}
	if err := createDNS01Records(ctx, cf, pending); err != nil {
		return nil, err
	}
	defer func() {
		for _, item := range pending {
			deleteTXT(ctx, cf, item.recID)
		}
	}()
	for _, item := range pending {
		if err := waitTXT(ctx, item.fqdn, item.val); err != nil {
			return nil, err
		}
	}
	for _, item := range pending {
		if _, err := client.Accept(ctx, item.chal); err != nil {
			return nil, err
		}
	}
	for _, item := range pending {
		if _, err := client.WaitAuthorization(ctx, item.authz.URI); err != nil {
			return nil, err
		}
	}
	if order.URI != "" {
		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, fmt.Errorf("acme wait order: %w", err)
		}
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr.Raw, true)
	if err != nil {
		return nil, fmt.Errorf("acme finalize: %w", err)
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	var buf bytes.Buffer
	for _, c := range der {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, err
	}
	return &Result{
		ChainPEM:    buf.String(),
		Fingerprint: FingerprintSHA256(der[0]),
		NotAfter:    leaf.NotAfter,
		Issuer:      "Let's Encrypt",
	}, nil
}

func acmeAccount(email string) (*acme.Account, error) {
	email = strings.TrimSpace(email)
	if strings.HasPrefix(strings.ToLower(email), "mailto:") {
		email = strings.TrimSpace(email[len("mailto:"):])
	}
	if email == "" {
		return nil, fmt.Errorf("acme email required")
	}
	return &acme.Account{Contact: []string{"mailto:" + email}}, nil
}

func isAlreadyReg(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already")
}

func zoneCandidates(domain string) []string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return nil
	}
	out := make([]string, 0, len(labels)-1)
	for i := 0; i < len(labels)-1; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

type pendingChal struct {
	chal  *acme.Challenge
	authz *acme.Authorization
	fqdn  string
	name  string
	val   string
	recID string
}

func createDNS01Records(ctx context.Context, cf Cloudflare, pending []pendingChal) error {
	for i := range pending {
		recID, err := createTXT(ctx, cf, pending[i].name, pending[i].val)
		if err != nil {
			return fmt.Errorf("dns-01 txt %s: %w", pending[i].name, err)
		}
		pending[i].recID = recID
	}
	return nil
}

func challengeFQDN(domain string) string {
	return ChallengeHost(domain)
}

func txtRecordName(domain, zoneName string) string {
	fqdn := challengeFQDN(domain)
	zoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
	if zoneName != "" && strings.HasSuffix(fqdn, "."+zoneName) {
		rel := strings.TrimSuffix(fqdn, "."+zoneName)
		if rel == "" {
			return "@"
		}
		return rel
	}
	return fqdn
}

func resolveZone(ctx context.Context, token, domain string) (string, string, error) {
	for _, name := range zoneCandidates(domain) {
		id, zoneName, err := lookupCloudflareZone(ctx, token, name)
		if err != nil {
			return "", "", err
		}
		if id != "" {
			return id, zoneName, nil
		}
	}
	return "", "", fmt.Errorf("cloudflare zone not found for %s", domain)
}

func lookupCloudflareZone(ctx context.Context, token, name string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfAPIBase+"/zones?name="+url.QueryEscape(name), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", err
	}
	if !out.Success {
		msg := "cloudflare zone lookup failed"
		if len(out.Errors) > 0 {
			msg = out.Errors[0].Message
		}
		return "", "", fmt.Errorf("%s", msg)
	}
	for _, zone := range out.Result {
		if strings.EqualFold(zone.Name, name) && zone.ID != "" {
			return zone.ID, zone.Name, nil
		}
	}
	return "", "", nil
}

func waitTXT(ctx context.Context, host, value string) error {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for {
		txts, err := lookupTXT(ctx, host)
		if err == nil {
			for _, txt := range txts {
				if txt == value {
					if txtSettle > 0 {
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(txtSettle):
						}
					}
					return nil
				}
			}
			last = fmt.Errorf("txt record not visible yet for %s", host)
		} else {
			last = err
		}
		if !time.Now().Before(deadline) {
			if last == nil {
				last = fmt.Errorf("txt record not visible yet for %s", host)
			}
			return last
		}
		wait := txtPoll
		if wait <= 0 {
			wait = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func upsertTXT(ctx context.Context, cf Cloudflare, name, fqdn, content string) (string, error) {
	if id, err := createTXT(ctx, cf, name, content); err == nil {
		return id, nil
	} else if id, upErr := updateTXT(ctx, cf, fqdn, content); upErr == nil {
		return id, nil
	} else {
		return "", err
	}
}

func createTXT(ctx context.Context, cf Cloudflare, name, content string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"type": "TXT", "name": name, "content": content, "ttl": 60,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/zones/%s/dns_records", cfAPIBase, cf.ZoneID),
		bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if !out.Success {
		msg := "cloudflare dns create failed"
		if len(out.Errors) > 0 {
			msg = out.Errors[0].Message
		}
		return "", fmt.Errorf("%s", msg)
	}
	return out.Result.ID, nil
}

func updateTXT(ctx context.Context, cf Cloudflare, fqdn, content string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/zones/%s/dns_records?type=TXT&name=%s", cfAPIBase, cf.ZoneID, url.QueryEscape(fqdn)), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var listed struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil || !listed.Success || len(listed.Result) == 0 {
		return "", fmt.Errorf("cloudflare txt record not found")
	}
	id := listed.Result[0].ID
	body, _ := json.Marshal(map[string]any{
		"type": "TXT", "content": content, "ttl": 60,
	})
	req, err = http.NewRequestWithContext(ctx, http.MethodPatch,
		fmt.Sprintf("%s/zones/%s/dns_records/%s", cfAPIBase, cf.ZoneID, id), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ = io.ReadAll(resp.Body)
	var out struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if !out.Success {
		msg := "cloudflare dns update failed"
		if len(out.Errors) > 0 {
			msg = out.Errors[0].Message
		}
		return "", fmt.Errorf("%s", msg)
	}
	return id, nil
}

func deleteTXT(ctx context.Context, cf Cloudflare, id string) {
	if id == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/dns_records/%s", cfAPIBase, cf.ZoneID, id), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
