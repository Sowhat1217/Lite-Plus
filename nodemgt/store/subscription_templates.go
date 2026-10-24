package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Store) ListSubscriptionTemplates() ([]models.SubscriptionTemplate, error) {
	rows := []models.SubscriptionTemplate{}
	err := s.db.Order("name ASC, id ASC").Find(&rows).Error
	return rows, err
}

func (s *Store) GetSubscriptionTemplate(id string) (*models.SubscriptionTemplate, error) {
	var row models.SubscriptionTemplate
	err := s.db.First(&row, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrNotFound
	}
	return &row, err
}

func (s *Store) UpsertSubscriptionTemplate(row *models.SubscriptionTemplate) error {
	switch row.Kind {
	case "clash", "loon", "surge", "sing-box":
	default:
		return fmt.Errorf("%w: unsupported template kind", ErrInvalid)
	}
	row.Name = strings.TrimSpace(row.Name)
	if row.Name == "" || len(row.Name) > 100 || row.Content == "" || len(row.Content) > 1024*1024 {
		return fmt.Errorf("%w: template name and content required (maximum 1 MiB)", ErrInvalid)
	}
	if row.ID == "" {
		row.ID, row.Revision, row.CreatedAt, row.UpdatedAt = newID(), 1, now(), now()
		return s.db.Create(row).Error
	}
	// The template kind is immutable while bindings may reference it.
	return s.db.Transaction(func(tx *gorm.DB) error {
		old, err := New(tx).GetSubscriptionTemplate(row.ID)
		if err != nil {
			return err
		}
		if old.Kind != row.Kind {
			return fmt.Errorf("%w: create a new template to change its kind", ErrInvalid)
		}
		row.CreatedAt, row.UpdatedAt = old.CreatedAt, now()
		if err := tx.Model(old).Updates(map[string]any{"name": row.Name, "content": row.Content, "revision": gorm.Expr("revision + 1"), "updated_at": row.UpdatedAt}).Error; err != nil {
			return err
		}
		return tx.First(row, "id = ?", row.ID).Error
	})
}

func (s *Store) DeleteSubscriptionTemplate(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&models.SubscriptionTemplateBinding{}).Where("template_id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("%w: remove template bindings first", ErrConflict)
		}
		result := tx.Delete(&models.SubscriptionTemplate{}, "id = ?", id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) ListSubscriptionTemplateBindings() ([]models.SubscriptionTemplateBinding, error) {
	rows := []models.SubscriptionTemplateBinding{}
	err := s.db.Order("scope ASC, scope_id ASC, client ASC").Find(&rows).Error
	return rows, err
}

func (s *Store) SetSubscriptionTemplateBinding(row *models.SubscriptionTemplateBinding) error {
	return s.db.Transaction(func(tx *gorm.DB) error { return New(tx).setSubscriptionTemplateBinding(row) })
}

func (s *Store) setSubscriptionTemplateBinding(row *models.SubscriptionTemplateBinding) error {
	if TemplateKindForClient(row.Client) == "" {
		return fmt.Errorf("%w: unsupported template client", ErrInvalid)
	}
	switch row.Scope {
	case "global":
		if row.ScopeID != "" {
			return fmt.Errorf("%w: global scope_id must be empty", ErrInvalid)
		}
	case "subscription":
		var sub models.Subscription
		if err := s.db.First(&sub, "id = ?", row.ScopeID).Error; err != nil {
			return ErrNotFound
		}
	case "plan":
		if _, err := s.GetPlan(row.ScopeID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: invalid template binding scope", ErrInvalid)
	}
	query := s.db.Where("scope = ? AND scope_id = ? AND client = ?", row.Scope, row.ScopeID, row.Client)
	if row.TemplateID == "" {
		return query.Delete(&models.SubscriptionTemplateBinding{}).Error
	}
	tpl, err := s.GetSubscriptionTemplate(row.TemplateID)
	if err != nil {
		return err
	}
	if tpl.Kind != TemplateKindForClient(row.Client) {
		return fmt.Errorf("%w: template kind does not match client", ErrInvalid)
	}
	row.ID, row.UpdatedAt = newID(), now()
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scope"}, {Name: "scope_id"}, {Name: "client"}},
		DoUpdates: clause.AssignmentColumns([]string{"template_id", "updated_at"}),
	}).Create(row).Error
}

func TemplateKindForClient(client string) string {
	switch client {
	case "mihomo", "clash", "stash":
		return "clash"
	case "surge", "surge-mac":
		return "surge"
	case "loon":
		return "loon"
	case "sing-box":
		return "sing-box"
	}
	return ""
}

func (s *Store) ResolveSubscriptionTemplate(row models.Subscription, client string) (*models.SubscriptionTemplate, error) {
	scopes := [][2]string{{"subscription", row.ID}}
	assignments, err := s.ListAssignments(row.UserID)
	if err != nil {
		return nil, err
	}
	for _, asg := range assignments {
		if asg.StartsAt.After(now()) || (asg.EndsAt != nil && !asg.EndsAt.After(now())) {
			continue
		}
		scopes = append(scopes, [2]string{"plan", asg.PlanID})
	}
	scopes = append(scopes, [2]string{"global", ""})
	for _, scope := range scopes {
		var binding models.SubscriptionTemplateBinding
		err := s.db.Where("scope = ? AND scope_id = ? AND client = ?", scope[0], scope[1], client).First(&binding).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return s.GetSubscriptionTemplate(binding.TemplateID)
	}
	return nil, nil
}
