package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/cert"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/secretcrypt"
	"github.com/nuomiiiii/lite/nodemgt/store"
	v2 "github.com/nuomiiiii/lite/protocol/v2"
	agent_runtime "github.com/nuomiiiii/lite/web/agent"
)

func EnqueueApplyConfig(st *store.Store, nodeUUID string) error {
	if strings.TrimSpace(nodeUUID) == "" {
		return nil
	}
	snap, err := st.NodeSnapshot(nodeUUID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return st.EnqueueCommand(&models.ControlCommand{
		NodeUUID:    nodeUUID,
		Kind:        "applyConfig",
		PayloadJSON: string(payload),
		Status:      models.CmdPending,
	})
}

func PushPending(st *store.Store, nodeUUID string) error {
	cmds, err := st.DueCommands(nodeUUID, 2*time.Minute)
	if err != nil {
		return err
	}
	for _, cmd := range cmds {
		PushCommand(st, cmd)
	}
	return nil
}

func commandPayloadJSON(cmd models.ControlCommand) string {
	if cmd.PayloadJSON == "" {
		return ""
	}
	plain, err := secretcrypt.Open(cmd.PayloadJSON)
	if err != nil {
		return cmd.PayloadJSON
	}
	return plain
}

func PushCommand(st *store.Store, cmd models.ControlCommand) {
	var payload any
	if raw := commandPayloadJSON(cmd); raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	agent_runtime.DispatchV2Event(cmd.NodeUUID, v2.MethodNodemgtControl, map[string]any{
		"operation_id": cmd.OperationID,
		"kind":         cmd.Kind,
		"payload":      payload,
	})
	if st != nil && agent_runtime.IsAgentOnline(cmd.NodeUUID) {
		_ = st.MarkCommandSent(cmd.OperationID)
	}
}

func Ack(st *store.Store, operationID, status, lastErr string) error {
	return st.AckCommand(operationID, status, lastErr)
}

type Result struct {
	NodeUUID    string
	OperationID string
	Status      string
	Error       string
	CSRPEM      string
	CertID      string
	Domain      string
	Fingerprint string
	Issuer      string
	NotAfter    *time.Time
}

func HandleResult(st *store.Store, r Result) error {
	if strings.TrimSpace(r.CSRPEM) == "" && strings.TrimSpace(r.CertID) != "" {
		if err := applyFileCertStatus(st, r); err != nil {
			return err
		}
	}
	if strings.TrimSpace(r.OperationID) == "" {
		if strings.TrimSpace(r.CertID) == "" {
			return fmt.Errorf("%w: operation_id", store.ErrInvalid)
		}
		return nil
	}
	cmd, err := st.GetCommand(r.OperationID)
	if err != nil {
		return err
	}
	if r.NodeUUID != "" && cmd.NodeUUID != r.NodeUUID {
		return store.ErrForbidden
	}
	if strings.TrimSpace(r.CSRPEM) != "" {
		if cmd.Kind != "needCSR" {
			return fmt.Errorf("%w: csr not allowed for %s", store.ErrInvalid, cmd.Kind)
		}
		if strings.EqualFold(r.Status, "failed") {
			return st.AckCommand(r.OperationID, r.Status, r.Error)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := completeCertFromCSR(ctx, st, *cmd, r.CSRPEM); err != nil {
			_ = st.AckCommand(r.OperationID, models.CmdFailed, err.Error())
			return err
		}
	}
	return st.AckCommand(r.OperationID, r.Status, r.Error)
}

func BindFileCert(st *store.Store, row *models.Certificate) error {
	if strings.TrimSpace(row.Domain) == "" || strings.TrimSpace(row.NodeUUID) == "" {
		return fmt.Errorf("%w: domain and node required", store.ErrInvalid)
	}
	if err := validAgentPath(row.CertPath); err != nil {
		return err
	}
	if err := validAgentPath(row.KeyPath); err != nil {
		return err
	}
	row.Source = models.CertSourceFile
	row.CertPath = strings.TrimSpace(row.CertPath)
	row.KeyPath = strings.TrimSpace(row.KeyPath)
	row.ChainPEM = ""
	row.Issuer = ""
	row.Fingerprint = ""
	row.NotAfter = nil
	row.Status = models.CertPending
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	if err := EnqueueApplyConfig(st, row.NodeUUID); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func validAgentPath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("%w: cert and key paths required", store.ErrInvalid)
	}
	if strings.ContainsRune(p, 0) || len(p) > 512 {
		return fmt.Errorf("%w: path", store.ErrInvalid)
	}
	return nil
}

func applyFileCertStatus(st *store.Store, r Result) error {
	row, err := st.GetCert(r.CertID)
	if err != nil {
		return err
	}
	if r.NodeUUID != "" && row.NodeUUID != r.NodeUUID {
		return store.ErrForbidden
	}
	if row.Source != models.CertSourceFile {
		return nil
	}
	if strings.EqualFold(r.Status, "failed") {
		row.Status = models.CertFailed
		row.LastError = r.Error
		return st.UpsertCert(row)
	}
	if r.Fingerprint != "" {
		row.Fingerprint = r.Fingerprint
	}
	if issuer := clipIssuer(r.Issuer); issuer != "" {
		row.Issuer = issuer
	}
	if r.NotAfter != nil {
		row.NotAfter = r.NotAfter
	}
	if r.Fingerprint != "" || r.NotAfter != nil {
		row.Status = models.CertIssued
		row.LastError = ""
	}
	return st.UpsertCert(row)
}

func clipIssuer(s string) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) > 64 {
		return string(runes[:64])
	}
	return s
}

func completeCertFromCSR(ctx context.Context, st *store.Store, cmd models.ControlCommand, csrPEM string) error {
	var payload struct {
		CertID string `json:"cert_id"`
		Domain string `json:"domain"`
		TestCA bool   `json:"test_ca"`
	}
	_ = json.Unmarshal([]byte(commandPayloadJSON(cmd)), &payload)
	certID, domain, testCA := payload.CertID, payload.Domain, payload.TestCA
	if err := csrMatchesTask(csrPEM, domain); err != nil {
		return err
	}
	if certID == "" {
		return nil
	}
	row, err := st.GetCert(certID)
	if err != nil {
		return err
	}
	if cmd.NodeUUID != "" && row.NodeUUID != cmd.NodeUUID {
		return store.ErrForbidden
	}
	if domain == "" {
		domain = row.Domain
	}
	var issued *cert.Result
	if testCA {
		issued, err = cert.IssueLocalTestCA(domain, csrPEM)
	} else {
		token, _ := st.GetSetting("cf_api_token")
		zone, _ := st.GetSetting("cf_zone_id")
		email, _ := st.GetSetting("acme_email")
		issued, err = cert.IssueACME(ctx, cert.Request{
			Domain: domain,
			Email:  email,
			CSRPEM: csrPEM,
			CF:     cert.Cloudflare{APIToken: token, ZoneID: zone},
		})
	}
	if err != nil {
		row.Status = models.CertFailed
		row.LastError = err.Error()
		return st.UpsertCert(row)
	}
	return ApplyIssuedCert(st, row, issued, domain)
}

func ApplyIssuedCert(st *store.Store, row *models.Certificate, issued *cert.Result, domain string) error {
	if domain == "" {
		domain = row.Domain
	}
	row.Status = models.CertIssued
	row.Source = models.CertSourceACME
	row.CertPath = ""
	row.KeyPath = ""
	row.ChainPEM = issued.ChainPEM
	row.Fingerprint = issued.Fingerprint
	row.Issuer = issued.Issuer
	row.NotAfter = &issued.NotAfter
	row.LastError = ""
	if err := st.UpsertCert(row); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"domain":    domain,
		"cert_id":   row.ID,
		"chain_pem": issued.ChainPEM,
	})
	if err != nil {
		return err
	}
	apply := &models.ControlCommand{
		NodeUUID:    row.NodeUUID,
		Kind:        "applyCert",
		PayloadJSON: string(payload),
	}
	if err := st.EnqueueCommand(apply); err != nil {
		return err
	}
	return PushPending(st, row.NodeUUID)
}

func csrMatchesTask(csrPEM, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("%w: domain", store.ErrInvalid)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return fmt.Errorf("%w: csr", store.ErrInvalid)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" && !strings.EqualFold(cn, domain) {
		return fmt.Errorf("%w: csr cn", store.ErrForbidden)
	}
	if len(csr.DNSNames) == 0 && (csr.Subject.CommonName == "" || !strings.EqualFold(csr.Subject.CommonName, domain)) {
		return fmt.Errorf("%w: csr san", store.ErrForbidden)
	}
	for _, name := range csr.DNSNames {
		if !strings.EqualFold(strings.TrimSpace(name), domain) {
			return fmt.Errorf("%w: csr san", store.ErrForbidden)
		}
	}
	return nil
}
