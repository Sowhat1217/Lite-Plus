package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestACMEAccountRequiresEmail(t *testing.T) {
	if _, err := acmeAccount(""); err == nil {
		t.Fatal("empty email should fail")
	}
	if _, err := acmeAccount("  mailto:  "); err == nil {
		t.Fatal("blank mailto should fail")
	}
	want := []string{"mailto:ops@example.com"}
	got, err := acmeAccount("ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Contact, want) {
		t.Fatalf("Contact = %v; want %v", got.Contact, want)
	}
	got, err = acmeAccount(" mailto:ops@example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Contact, want) {
		t.Fatalf("prefixed Contact = %v; want %v", got.Contact, want)
	}
}

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("www.api.example.com")
	want := []string{"www.api.example.com", "api.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if zoneCandidates("localhost") != nil {
		t.Fatal("single label should be empty")
	}
}

func TestTxtRecordNameIsRelativeToZone(t *testing.T) {
	got := txtRecordName("test.8787837.xyz", "8787837.xyz")
	if got != "_acme-challenge.test" {
		t.Fatalf("got %s", got)
	}
	if txtRecordName("8787837.xyz", "8787837.xyz") != "_acme-challenge" {
		t.Fatal("apex")
	}
}

func TestWaitTXTSeesValue(t *testing.T) {
	prevLookup, prevSettle, prevPoll := lookupTXT, txtSettle, txtPoll
	t.Cleanup(func() {
		lookupTXT, txtSettle, txtPoll = prevLookup, prevSettle, prevPoll
	})
	txtSettle = 0
	txtPoll = 0
	lookupTXT = func(context.Context, string) ([]string, error) {
		return []string{"token-value"}, nil
	}
	if err := waitTXT(context.Background(), "_acme-challenge.test.example.com", "token-value"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveZoneLooksUpApex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		if name != "example.com" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result":  []map[string]string{{"id": "zone-1", "name": "example.com"}},
		})
	}))
	t.Cleanup(srv.Close)
	prev := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = prev })
	id, name, err := resolveZone(context.Background(), "tok", "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != "zone-1" || name != "example.com" {
		t.Fatalf("zone %s %s", id, name)
	}
}

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
