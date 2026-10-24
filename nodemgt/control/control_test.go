package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/utils/instancekey"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	cleanup := instancekey.SetupTempFileForTest()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{NowFunc: func() time.Time { return time.Now().UTC() }})
	require.NoError(t, err)
	st := store.New(db)
	require.NoError(t, st.Migrate())
	return st
}

func testCSR(t *testing.T, domain string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
	}, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestHandleResultCompletesCSR(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "nodemgt.test", Status: models.CertPending}
	require.NoError(t, st.UpsertCert(row))
	cmd := &models.ControlCommand{
		OperationID: "op-csr",
		NodeUUID:    "n1",
		Kind:        "needCSR",
		PayloadJSON: `{"domain":"nodemgt.test","cert_id":"` + row.ID + `","test_ca":true}`,
	}
	require.NoError(t, st.EnqueueCommand(cmd))
	err := HandleResult(st, Result{
		OperationID: "op-csr",
		Status:      "applied",
		CSRPEM:      testCSR(t, "nodemgt.test"),
		CertID:      row.ID,
		Domain:      "nodemgt.test",
	})
	require.NoError(t, err)
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.NotEmpty(t, got.ChainPEM)
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	require.Equal(t, "applyCert", pending[0].Kind)
}

func TestEnqueueApplyConfig(t *testing.T) {
	st := testStore(t)
	require.NoError(t, EnqueueApplyConfig(st, "n1"))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "applyConfig", pending[0].Kind)
	require.NoError(t, EnqueueApplyConfig(st, ""))
	pending, err = st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
}

func TestEnqueueApplyConfigSealsSecrets(t *testing.T) {
	st := testStore(t)
	user := &models.NodeUser{NodeUUID: "n1", Username: "alice"}
	require.NoError(t, st.UpsertUser(user))
	_, plain, err := st.IssueCredential(user.ID, "trojan", "audit-protocol-secret", nil)
	require.NoError(t, err)
	require.NoError(t, EnqueueApplyConfig(st, "n1"))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, strings.HasPrefix(pending[0].PayloadJSON, "enc:v1:"))
	require.False(t, strings.Contains(pending[0].PayloadJSON, plain))
	opened := commandPayloadJSON(pending[0])
	require.Contains(t, opened, plain)
}

func TestHandleResultRejectsOtherNode(t *testing.T) {
	st := testStore(t)
	cmd := &models.ControlCommand{OperationID: "op-a", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(cmd))
	err := HandleResult(st, Result{NodeUUID: "n2", OperationID: "op-a", Status: "applied"})
	require.ErrorIs(t, err, store.ErrForbidden)
	got, err := st.GetCommand("op-a")
	require.NoError(t, err)
	require.Equal(t, models.CmdPending, got.Status)
}

func TestHandleResultWithoutCSROnlyAcks(t *testing.T) {
	st := testStore(t)
	cmd := &models.ControlCommand{OperationID: "op-ok", NodeUUID: "n1", Kind: "applyConfig", PayloadJSON: "{}"}
	require.NoError(t, st.EnqueueCommand(cmd))
	require.NoError(t, HandleResult(st, Result{OperationID: "op-ok", Status: "applied"}))
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 0)
}

func TestBindFileCertEnqueuesApplyConfig(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "panel.example",
		CertPath: "/opt/1panel/ssl/fullchain.pem",
		KeyPath:  "/opt/1panel/ssl/privkey.pem",
	}
	require.NoError(t, BindFileCert(st, row))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertSourceFile, got.Source)
	require.Equal(t, models.CertPending, got.Status)
	require.Empty(t, got.Issuer)
	require.Empty(t, got.ChainPEM)
	pending, err := st.PendingCommands("n1")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "applyConfig", pending[0].Kind)
	opened := commandPayloadJSON(pending[0])
	require.Contains(t, opened, "/opt/1panel/ssl/fullchain.pem")
	require.Contains(t, opened, "/opt/1panel/ssl/privkey.pem")
	require.Contains(t, opened, `"source":"file"`)
}

func TestBindFileCertRejectsEmptyPath(t *testing.T) {
	st := testStore(t)
	err := BindFileCert(st, &models.Certificate{NodeUUID: "n1", Domain: "panel.example", CertPath: "/c.pem"})
	require.ErrorIs(t, err, store.ErrInvalid)
}

func TestHandleResultUpdatesFileCert(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{
		NodeUUID: "n1",
		Domain:   "panel.example",
		Source:   models.CertSourceFile,
		CertPath: "/c.pem",
		KeyPath:  "/k.pem",
	}
	require.NoError(t, st.UpsertCert(row))
	notAfter := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, HandleResult(st, Result{
		NodeUUID:    "n1",
		CertID:      row.ID,
		Status:      "applied",
		Fingerprint: "abc123",
		Issuer:      "Let's Encrypt",
		NotAfter:    &notAfter,
	}))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertIssued, got.Status)
	require.Equal(t, "abc123", got.Fingerprint)
	require.Equal(t, "Let's Encrypt", got.Issuer)
	require.NotNil(t, got.NotAfter)
	require.True(t, got.NotAfter.Equal(notAfter))
}

func TestHandleResultFileCertRejectsOtherNode(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "panel.example", Source: models.CertSourceFile, CertPath: "/c.pem", KeyPath: "/k.pem"}
	require.NoError(t, st.UpsertCert(row))
	err := HandleResult(st, Result{NodeUUID: "n2", CertID: row.ID, Status: "applied", Fingerprint: "abc"})
	require.ErrorIs(t, err, store.ErrForbidden)
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertPending, got.Status)
}

func TestHandleResultIgnoresFileStatusForACMECert(t *testing.T) {
	st := testStore(t)
	row := &models.Certificate{NodeUUID: "n1", Domain: "acme.example", Status: models.CertPending}
	require.NoError(t, st.UpsertCert(row))
	require.NoError(t, HandleResult(st, Result{NodeUUID: "n1", CertID: row.ID, Status: "applied", Fingerprint: "abc"}))
	got, err := st.GetCert(row.ID)
	require.NoError(t, err)
	require.Equal(t, models.CertPending, got.Status)
	require.Empty(t, got.Fingerprint)
}
