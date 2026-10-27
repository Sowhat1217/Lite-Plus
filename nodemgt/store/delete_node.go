package store

import (
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

func (s *Store) DeleteNode(nodeUUID string) error {
	return deleteNodeTx(s.db, nodeUUID)
}

func (s *Store) PurgeMissingNodes() error {
	return purgeMissingNodesTx(s.db)
}

func deleteNodeTx(tx *gorm.DB, nodeUUID string) error {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return nil
	}
	if !tx.Migrator().HasTable(&models.Inbound{}) {
		return nil
	}
	var inboundIDs []string
	if err := tx.Model(&models.Inbound{}).Where("node_uuid = ?", nodeUUID).Pluck("id", &inboundIDs).Error; err != nil {
		return err
	}
	if len(inboundIDs) > 0 {
		if err := deleteWhere(tx, &models.Grant{}, "inbound_id IN ?", inboundIDs); err != nil {
			return err
		}
	}
	var userIDs []string
	if tx.Migrator().HasTable(&models.NodeUser{}) {
		if err := tx.Model(&models.NodeUser{}).Where("node_uuid = ?", nodeUUID).Pluck("id", &userIDs).Error; err != nil {
			return err
		}
	}
	if len(userIDs) > 0 {
		if err := deleteWhere(tx, &models.Credential{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.Assignment{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.QuotaLedger{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.QuotaLease{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.UserExtraLink{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.Grant{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if tx.Migrator().HasTable(&models.Subscription{}) && tx.Migrator().HasTable(&models.SubscriptionTemplateBinding{}) {
			if err := tx.Where("scope = ? AND scope_id IN (?)", "subscription", tx.Model(&models.Subscription{}).Select("id").Where("user_id IN ?", userIDs)).
				Delete(&models.SubscriptionTemplateBinding{}).Error; err != nil {
				return err
			}
		}
		if err := deleteWhere(tx, &models.Subscription{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := deleteWhere(tx, &models.UserIP{}, "user_id IN ?", userIDs); err != nil {
			return err
		}
		if err := tx.Where("id IN ?", userIDs).Delete(&models.NodeUser{}).Error; err != nil {
			return err
		}
	}
	if err := deleteWhere(tx, &models.UserIP{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	if err := deleteWhere(tx, &models.Inbound{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	if err := deleteWhere(tx, &models.Outbound{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	if err := deleteWhere(tx, &models.Route{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	if err := deleteWhere(tx, &models.Certificate{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	if err := deleteWhere(tx, &models.NodeProfile{}, "node_uuid = ?", nodeUUID); err != nil {
		return err
	}
	return deleteWhere(tx, &models.ControlCommand{}, "node_uuid = ?", nodeUUID)
}

func purgeMissingNodesTx(tx *gorm.DB) error {
	if !tx.Migrator().HasTable("clients") || !tx.Migrator().HasTable(&models.Inbound{}) {
		return nil
	}
	var live []string
	if err := tx.Table("clients").Pluck("uuid", &live).Error; err != nil {
		return err
	}
	keep := make(map[string]struct{}, len(live))
	for _, id := range live {
		id = strings.TrimSpace(id)
		if id != "" {
			keep[id] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	add := func(model any) error {
		if !tx.Migrator().HasTable(model) {
			return nil
		}
		var ids []string
		if err := tx.Model(model).Distinct("node_uuid").Pluck("node_uuid", &ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id != "" {
				seen[id] = struct{}{}
			}
		}
		return nil
	}
	for _, model := range []any{
		&models.Inbound{},
		&models.Outbound{},
		&models.Route{},
		&models.NodeUser{},
		&models.Certificate{},
		&models.ControlCommand{},
		&models.NodeProfile{},
		&models.UserIP{},
	} {
		if err := add(model); err != nil {
			return err
		}
	}
	for id := range seen {
		if _, ok := keep[id]; ok {
			continue
		}
		if err := deleteNodeTx(tx, id); err != nil {
			return err
		}
	}
	return nil
}

func deleteWhere(tx *gorm.DB, model any, query string, args ...any) error {
	if !tx.Migrator().HasTable(model) {
		return nil
	}
	return tx.Where(query, args...).Delete(model).Error
}
