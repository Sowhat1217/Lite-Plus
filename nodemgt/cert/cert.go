package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const DefaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"

type Cloudflare struct {
	APIToken string
	ZoneID   string
}

type Request struct {
	Domain    string
	Email     string
	Directory string
	CSRPEM    string
	CF        Cloudflare
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
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
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
	if req.CF.APIToken == "" || req.CF.ZoneID == "" {
		return nil, fmt.Errorf("cloudflare dns-01 credentials missing")
	}
	csr, err := ParseCSR(req.CSRPEM)
	if err != nil {
		return nil, err
	}
	dir := req.Directory
	if dir == "" {
		dir = DefaultDirectory
	}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: dir}
	acct := &acme.Account{Contact: []string{"mailto:" + req.Email}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !isAlreadyReg(err) {
		return nil, fmt.Errorf("acme register: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(req.Domain))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
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
		recID, err := upsertTXT(ctx, req.CF, "_acme-challenge."+req.Domain, val)
		if err != nil {
			return nil, err
		}
		defer deleteTXT(ctx, req.CF, recID)
		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, err
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return nil, err
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
		Issuer:      "letsencrypt",
	}, nil
}

func isAlreadyReg(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already")
}

func upsertTXT(ctx context.Context, cf Cloudflare, name, content string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"type": "TXT", "name": name, "content": content, "ttl": 60,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", cf.ZoneID),
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

func deleteTXT(ctx context.Context, cf Cloudflare, id string) {
	if id == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", cf.ZoneID, id), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
