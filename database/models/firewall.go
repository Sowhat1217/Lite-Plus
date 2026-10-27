package models

import "time"

// ClientFirewallIntent is the per-node desired firewall state stored on the
// control plane. Agent reinstalls pull this row back down by UUID.
type ClientFirewallIntent struct {
	Client            string     `json:"-" gorm:"type:varchar(36);primaryKey"`
	Revision          uint64     `json:"revision" gorm:"not null;default:0"`
	BlockPing4        bool       `json:"block_ping_v4" gorm:"not null;default:false"`
	BlockPing6        bool       `json:"block_ping_v6" gorm:"not null;default:false"`
	DefaultDeny4      bool       `json:"default_deny_v4" gorm:"not null;default:false"`
	DefaultDeny6      bool       `json:"default_deny_v6" gorm:"not null;default:false"`
	SshPort           string     `json:"ssh_port" gorm:"type:varchar(16);not null;default:''"`
	OmitKeep          string     `json:"-" gorm:"type:varchar(256);not null;default:''"`
	RulesJSON         string     `json:"-" gorm:"type:longtext;not null"`
	DeliveryStatus    string     `json:"delivery_status" gorm:"type:varchar(16);not null;default:''"`
	DeliveryError     string     `json:"delivery_error" gorm:"type:varchar(512);not null;default:''"`
	AppliedRevision   uint64     `json:"applied_revision" gorm:"not null;default:0"`
	SnapshotJSON      string     `json:"-" gorm:"type:longtext;not null;default:''"`
	SnapshotAt        *time.Time `json:"snapshot_at,omitempty"`
	DeliveryUpdatedAt *time.Time `json:"delivery_updated_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (ClientFirewallIntent) TableName() string {
	return "client_firewall_intents"
}
