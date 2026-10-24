package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestIssueLocalTestCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "nodemgt.test"}, DNSNames: []string{"nodemgt.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	got, err := IssueLocalTestCA("nodemgt.test", csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint == "" || got.ChainPEM == "" {
		t.Fatal("missing cert")
	}
	if got.Issuer != "lite-nodemgt-test-ca" {
		t.Fatalf("issuer %s", got.Issuer)
	}
}
