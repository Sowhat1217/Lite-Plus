package store

import (
	"errors"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/inboundcfg"
	"github.com/nuomiiiii/lite/nodemgt/models"
)

type snapshotCredential struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	UUID      string     `json:"uuid"`
	Secret    string     `json:"secret"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type snapshotUser struct {
	models.NodeUser
	InboundIDs  []string             `json:"inbound_ids"`
	Credentials []snapshotCredential `json:"credentials"`
}

func (s *Store) ListUsersOnNode(nodeUUID string) ([]models.NodeUser, error) {
	if strings.TrimSpace(nodeUUID) == "" {
		return s.ListUsers("")
	}
	inbounds, err := s.ListInbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	inboundIDs := make([]string, 0, len(inbounds))
	for _, in := range inbounds {
		inboundIDs = append(inboundIDs, in.ID)
	}
	var granted []string
	if len(inboundIDs) > 0 {
		if err := s.db.Model(&models.Grant{}).Where("inbound_id IN ?", inboundIDs).Distinct("user_id").Pluck("user_id", &granted).Error; err != nil {
			return nil, err
		}
	}
	var rows []models.NodeUser
	q := s.db.Where("node_uuid = ?", nodeUUID)
	if len(granted) > 0 {
		q = s.db.Where("node_uuid = ? OR id IN ?", nodeUUID, granted)
	}
	return rows, q.Order("created_at ASC").Find(&rows).Error
}

func (s *Store) NodeIDsForUser(userID string) ([]string, error) {
	seen := map[string]struct{}{}
	if user, err := s.GetUser(userID); err == nil && strings.TrimSpace(user.NodeUUID) != "" {
		seen[user.NodeUUID] = struct{}{}
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	grants, err := s.ListGrants(userID)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return mapKeys(seen), nil
	}
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.InboundID)
	}
	var inbounds []models.Inbound
	if err := s.db.Where("id IN ?", ids).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for _, in := range inbounds {
		if in.NodeUUID != "" {
			seen[in.NodeUUID] = struct{}{}
		}
	}
	return mapKeys(seen), nil
}

func (s *Store) UserOnNode(userID, nodeUUID string) error {
	if strings.TrimSpace(nodeUUID) == "" {
		return nil
	}
	nodes, err := s.NodeIDsForUser(userID)
	if err != nil {
		return err
	}
	for _, id := range nodes {
		if id == nodeUUID {
			return nil
		}
	}
	return ErrForbidden
}

func (s *Store) NodeSnapshot(nodeUUID string) (map[string]any, error) {
	inbounds, err := s.ListInbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	outbounds, err := s.ListOutbounds(nodeUUID)
	if err != nil {
		return nil, err
	}
	routes, err := s.ListRoutes(nodeUUID)
	if err != nil {
		return nil, err
	}
	users, err := s.ListUsersOnNode(nodeUUID)
	if err != nil {
		return nil, err
	}
	inboundIDs := map[string]struct{}{}
	for _, in := range inbounds {
		inboundIDs[in.ID] = struct{}{}
	}
	snapUsers := make([]snapshotUser, 0, len(users))
	for _, u := range users {
		view := snapshotUser{NodeUser: u, InboundIDs: []string{}}
		grants, err := s.ListGrants(u.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if _, ok := inboundIDs[g.InboundID]; ok {
				view.InboundIDs = append(view.InboundIDs, g.InboundID)
			}
		}
		creds, err := s.ListCredentials(u.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range creds {
			secret := c.SecretMaterial
			if secret == "" {
				secret = c.UUID
			}
			view.Credentials = append(view.Credentials, snapshotCredential{
				ID:        c.ID,
				Kind:      c.Kind,
				UUID:      c.UUID,
				Secret:    secret,
				Enabled:   c.Enabled,
				ExpiresAt: c.ExpiresAt,
			})
		}
		if plan, ok := assignedPlan(s, u.ID); ok {
			view.RateLimitBps = plan.RateLimitBps
		}
		snapUsers = append(snapUsers, view)
	}
	certs, err := s.ListCerts(nodeUUID)
	if err != nil {
		return nil, err
	}
	for i := range inbounds {
		inbounds[i].SettingsJSON = inboundcfg.NormalizeSniffSettingsJSON(inbounds[i].SettingsJSON)
	}
	return map[string]any{
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routes":    routes,
		"users":     snapUsers,
		"certs":     certs,
	}, nil
}

func assignedPlan(s *Store, userID string) (*models.Plan, bool) {
	asg, err := s.ListAssignments(userID)
	if err != nil || len(asg) == 0 {
		return nil, false
	}
	plan, err := s.GetPlan(asg[0].PlanID)
	if err != nil || plan == nil {
		return nil, false
	}
	return plan, true
}

func mapKeys(seen map[string]struct{}) []string {
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
