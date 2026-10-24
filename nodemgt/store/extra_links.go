package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

func (s *Store) extraLinksByUser() (map[string][]models.UserExtraLink, error) {
	var rows []models.UserExtraLink
	if err := s.db.Order("sort_index ASC, created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string][]models.UserExtraLink{}
	for _, row := range rows {
		out[row.UserID] = append(out[row.UserID], row)
	}
	return out, nil
}

func (s *Store) ListUserExtraLinks(userID string) ([]models.UserExtraLink, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id", ErrInvalid)
	}
	var rows []models.UserExtraLink
	err := s.db.Where("user_id = ?", userID).Order("sort_index ASC, created_at ASC").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []models.UserExtraLink{}
	}
	return rows, nil
}

func (s *Store) ReplaceUserExtraLinks(userID string, rows []models.UserExtraLink) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("%w: user_id", ErrInvalid)
	}
	clean := make([]models.UserExtraLink, 0, len(rows))
	for i, row := range rows {
		kind := strings.ToLower(strings.TrimSpace(row.Kind))
		if kind == "" {
			kind = models.ExtraLinkKindLink
		}
		if kind != models.ExtraLinkKindLink && kind != models.ExtraLinkKindSubscription {
			return fmt.Errorf("%w: extra link kind", ErrInvalid)
		}
		value := strings.TrimSpace(row.Value)
		if row.Enabled && value == "" {
			return fmt.Errorf("%w: extra link value", ErrInvalid)
		}
		if value == "" {
			continue
		}
		if len(value) > 4096 {
			return fmt.Errorf("%w: extra link value too long", ErrInvalid)
		}
		id := strings.TrimSpace(row.ID)
		if id == "" {
			id = newID()
		}
		stamp := now()
		created := row.CreatedAt
		if created.IsZero() {
			created = stamp
		}
		clean = append(clean, models.UserExtraLink{
			ID:             id,
			UserID:         userID,
			Kind:           kind,
			Value:          value,
			Remark:         strings.TrimSpace(row.Remark),
			NamePrefix:     strings.TrimSpace(row.NamePrefix),
			Enabled:        row.Enabled,
			ExpiresAt:      row.ExpiresAt,
			SortIndex:      i,
			LastFetchAt:    row.LastFetchAt,
			LastFetchError: strings.TrimSpace(row.LastFetchError),
			CreatedAt:      created,
		})
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserExtraLink{}).Error; err != nil {
			return err
		}
		for i := range clean {
			if err := tx.Model(&models.UserExtraLink{}).Create(extraLinkAttrs(clean[i])).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func extraLinkAttrs(row models.UserExtraLink) map[string]any {
	return map[string]any{
		"id":               row.ID,
		"user_id":          row.UserID,
		"kind":             row.Kind,
		"value":            row.Value,
		"remark":           row.Remark,
		"name_prefix":      row.NamePrefix,
		"enabled":          row.Enabled,
		"expires_at":       row.ExpiresAt,
		"sort_index":       row.SortIndex,
		"last_fetch_at":    row.LastFetchAt,
		"last_fetch_error": row.LastFetchError,
		"created_at":       row.CreatedAt,
	}
}

func (s *Store) RecordUserExtraLinkFetch(id, errMsg string, at time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: extra link id", ErrInvalid)
	}
	if at.IsZero() {
		at = now()
	}
	return s.db.Model(&models.UserExtraLink{}).Where("id = ?", id).Updates(map[string]any{
		"last_fetch_at":    at,
		"last_fetch_error": strings.TrimSpace(errMsg),
	}).Error
}
