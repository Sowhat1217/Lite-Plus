package store

import (
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"gorm.io/gorm"
)

const (
	DialStackDual       = "dual"
	DialStackIPv4       = "ipv4"
	DialStackIPv6       = "ipv6"
	DialStackPreferIPv4 = "prefer_ipv4"
	DialStackPreferIPv6 = "prefer_ipv6"
)

func NormalizeDialStack(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case DialStackIPv4, "ipv4_only", "useipv4":
		return DialStackIPv4
	case DialStackIPv6, "ipv6_only", "useipv6":
		return DialStackIPv6
	case DialStackPreferIPv4, "useipv4v6":
		return DialStackPreferIPv4
	case DialStackPreferIPv6, "useipv6v4":
		return DialStackPreferIPv6
	default:
		return DialStackDual
	}
}

func (s *Store) NodeDialStack(nodeUUID string) string {
	row, err := s.GetNodeProfile(nodeUUID)
	if err != nil || row == nil {
		return DialStackDual
	}
	return NormalizeDialStack(row.DialStack)
}

func (s *Store) GetNodeProfile(nodeUUID string) (*models.NodeProfile, error) {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return nil, ErrNotFound
	}
	if !s.db.Migrator().HasTable(&models.NodeProfile{}) {
		return nil, ErrNotFound
	}
	var row models.NodeProfile
	if err := s.db.First(&row, "node_uuid = ?", nodeUUID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

func (s *Store) ListNodeProfiles() ([]models.NodeProfile, error) {
	if !s.db.Migrator().HasTable(&models.NodeProfile{}) {
		return nil, nil
	}
	var rows []models.NodeProfile
	if err := s.db.Order("node_uuid ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Store) UpsertNodeProfile(nodeUUID, dialStack string) (*models.NodeProfile, error) {
	nodeUUID = strings.TrimSpace(nodeUUID)
	if nodeUUID == "" {
		return nil, ErrNotFound
	}
	row := models.NodeProfile{
		NodeUUID:  nodeUUID,
		DialStack: NormalizeDialStack(dialStack),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.db.Save(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}
