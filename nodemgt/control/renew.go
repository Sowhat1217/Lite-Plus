package control

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
)

const (
	CertRenewWindow      = 30 * 24 * time.Hour
	CertRenewFailBackoff = 6 * time.Hour
	certRenewPendingAge  = 24 * time.Hour
)

var renewMu sync.Mutex

func RenewDue(ctx context.Context, st *store.Store, now time.Time, testCA bool) error {
	if !renewMu.TryLock() {
		return nil
	}
	defer renewMu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	openCSR, err := openNeedCSR(st)
	if err != nil {
		return err
	}
	var errs []error
	certs, err := st.ListCerts("")
	if err != nil {
		return err
	}
	for i := range certs {
		row := certs[i]
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if row.Source != models.CertSourceACME && row.Source != "" {
			continue
		}
		if row.Source == "" && (row.RootCertID != "" || row.CertPath != "") {
			continue
		}
		if !dueForRenew(row.AutoRenew, row.Status, row.NotAfter, row.UpdatedAt, now) {
			continue
		}
		if openCSR[row.ID] {
			continue
		}
		if err := RequestACME(st, &row, testCA); err != nil {
			errs = append(errs, err)
		} else {
			openCSR[row.ID] = true
		}
	}
	roots, err := st.ListRootCerts()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for i := range roots {
		row := roots[i]
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if !dueForRenew(row.AutoRenew, row.Status, row.NotAfter, row.UpdatedAt, now) {
			continue
		}
		if err := IssueRootCert(ctx, st, &row, testCA); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func dueForRenew(autoRenew bool, status string, notAfter *time.Time, updatedAt, now time.Time) bool {
	if !autoRenew || notAfter == nil {
		return false
	}
	if !notAfter.Before(now.Add(CertRenewWindow)) {
		return false
	}
	switch status {
	case models.CertIssued:
		return true
	case models.CertFailed:
		return now.Sub(updatedAt) >= CertRenewFailBackoff
	case models.CertPending:
		return now.Sub(updatedAt) >= certRenewPendingAge
	default:
		return false
	}
}

func openNeedCSR(st *store.Store) (map[string]bool, error) {
	var rows []models.ControlCommand
	err := st.DB().Where("kind = ? AND status IN ?", "needCSR", []string{models.CmdPending, models.CmdSent}).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, cmd := range rows {
		var payload struct {
			CertID string `json:"cert_id"`
		}
		if json.Unmarshal([]byte(cmd.PayloadJSON), &payload) != nil {
			continue
		}
		if payload.CertID != "" {
			out[payload.CertID] = true
		}
	}
	return out, nil
}
