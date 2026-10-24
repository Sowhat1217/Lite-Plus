package models

import "time"

const (
	CoreXray    = "xray"
	CoreSingBox = "sing-box"

	UserActive   = "active"
	UserDisabled = "disabled"
	UserExpired  = "expired"

	CmdPending    = "pending"
	CmdSent       = "sent"
	CmdApplied    = "applied"
	CmdFailed     = "failed"
	CmdSuperseded = "superseded"

	CertPending = "pending"
	CertIssued  = "issued"
	CertFailed  = "failed"

	CertSourceACME = "acme"
	CertSourceFile = "file"
)

type Inbound struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID     string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Core         string    `json:"core" gorm:"type:varchar(16);not null"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	Protocol     string    `json:"protocol" gorm:"type:varchar(32);not null"`
	Listen       string    `json:"listen" gorm:"type:varchar(128);not null;default:'0.0.0.0'"`
	Port         int       `json:"port" gorm:"not null"`
	SortIndex    int       `json:"sort_index" gorm:"not null;default:0;index"`
	SettingsJSON string    `json:"settings_json" gorm:"type:longtext"`
	StreamJSON   string    `json:"stream_json" gorm:"type:longtext"`
	Enabled      bool      `json:"enabled" gorm:"not null;default:true"`
	Revision     uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Inbound) TableName() string { return "nodemgt_inbounds" }

type Outbound struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID     string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Core         string    `json:"core" gorm:"type:varchar(16);not null"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	Protocol     string    `json:"protocol" gorm:"type:varchar(32);not null"`
	SettingsJSON string    `json:"settings_json" gorm:"type:longtext"`
	Enabled      bool      `json:"enabled" gorm:"not null;default:true"`
	Revision     uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Outbound) TableName() string { return "nodemgt_outbounds" }

type Route struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID  string    `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Name      string    `json:"name" gorm:"type:varchar(100);not null"`
	Priority  int       `json:"priority" gorm:"not null;default:0"`
	RuleJSON  string    `json:"rule_json" gorm:"type:longtext"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	Revision  uint64    `json:"revision" gorm:"not null;default:0"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Route) TableName() string { return "nodemgt_routes" }

type Grant struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	InboundID string    `json:"inbound_id" gorm:"type:varchar(36);index;not null"`
	CreatedAt time.Time `json:"created_at"`
}

func (Grant) TableName() string { return "nodemgt_grants" }

type NodeUser struct {
	ID                string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID          string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Username          string     `json:"username" gorm:"type:varchar(100);not null"`
	DisplayName       string     `json:"display_name" gorm:"type:varchar(100)"`
	Status            string     `json:"status" gorm:"type:varchar(16);not null;default:'active'"`
	ExpiresAt         *time.Time `json:"expires_at"`
	TrafficResetDay   int        `json:"traffic_reset_day" gorm:"not null;default:0"`
	TrafficResetCycle string     `json:"traffic_reset_cycle" gorm:"type:varchar(64)"`
	RateLimitBps      int64      `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit       int        `json:"device_limit" gorm:"not null;default:0"`
	QuotaBytes        int64      `json:"quota_bytes" gorm:"not null;default:0"`
	UsedBytes         int64      `json:"used_bytes" gorm:"not null;default:0"`
	Flow              string     `json:"flow" gorm:"type:varchar(64)"`
	SharedPoolID      string     `json:"shared_pool_id" gorm:"type:varchar(36);index"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	IPsClearedAt      *time.Time `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (NodeUser) TableName() string { return "nodemgt_node_users" }

type Credential struct {
	ID             string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID         string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Kind           string     `json:"kind" gorm:"type:varchar(16);not null"`
	SecretHash     string     `json:"-" gorm:"type:varchar(128);not null"`
	SecretHint     string     `json:"secret_hint" gorm:"type:varchar(16)"`
	SecretMaterial string     `json:"-" gorm:"type:longtext"`
	UUID           string     `json:"uuid,omitempty" gorm:"type:varchar(36)"`
	Enabled        bool       `json:"enabled" gorm:"not null;default:true"`
	ExpiresAt      *time.Time `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (Credential) TableName() string { return "nodemgt_credentials" }

type Plan struct {
	ID           string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	TrafficBytes int64     `json:"traffic_bytes" gorm:"not null;default:0"`
	DurationDays int       `json:"duration_days" gorm:"not null;default:30"`
	RateLimitBps int64     `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit  int       `json:"device_limit" gorm:"not null;default:0"`
	SharedPool   bool      `json:"shared_pool" gorm:"not null;default:false"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Plan) TableName() string { return "nodemgt_plans" }

type Assignment struct {
	ID           string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID       string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	PlanID       string     `json:"plan_id" gorm:"type:varchar(36);index;not null"`
	StartsAt     time.Time  `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at"`
	TrafficBytes int64      `json:"traffic_bytes" gorm:"not null;default:0"`
	RateLimitBps int64      `json:"rate_limit_bps" gorm:"not null;default:0"`
	DeviceLimit  int        `json:"device_limit" gorm:"not null;default:0"`
	OperationID  string     `json:"operation_id" gorm:"type:varchar(64);uniqueIndex"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (Assignment) TableName() string { return "nodemgt_assignments" }

type QuotaLedger struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Delta     int64     `json:"delta" gorm:"not null"`
	Reason    string    `json:"reason" gorm:"type:varchar(32);not null"`
	OpID      string    `json:"operation_id" gorm:"type:varchar(64);uniqueIndex"`
	CreatedAt time.Time `json:"created_at"`
}

func (QuotaLedger) TableName() string { return "nodemgt_quota_ledger" }

type QuotaLease struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	PoolID    string    `json:"pool_id" gorm:"type:varchar(36);index;not null"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Bytes     int64     `json:"bytes" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (QuotaLease) TableName() string { return "nodemgt_quota_leases" }

type Subscription struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Token     string    `json:"token" gorm:"type:varchar(64);uniqueIndex;not null"`
	TokenHash string    `json:"-" gorm:"type:varchar(64);index"`
	Format    string    `json:"format" gorm:"type:varchar(16);not null;default:'xray'"`
	ExtraURLs string    `json:"extra_urls" gorm:"type:longtext"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Subscription) TableName() string { return "nodemgt_subscriptions" }

const (
	ExtraLinkKindLink         = "link"
	ExtraLinkKindSubscription = "subscription"
)

type UserExtraLink struct {
	ID             string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID         string     `json:"user_id" gorm:"type:varchar(36);index;not null"`
	Kind           string     `json:"kind" gorm:"type:varchar(16);not null;default:'link'"`
	Value          string     `json:"value" gorm:"type:longtext;not null"`
	Remark         string     `json:"remark" gorm:"type:varchar(200)"`
	NamePrefix     string     `json:"name_prefix" gorm:"type:varchar(64)"`
	Enabled        bool       `json:"enabled" gorm:"not null;default:true"`
	ExpiresAt      *time.Time `json:"expires_at"`
	SortIndex      int        `json:"sort_index" gorm:"not null;default:0;index"`
	LastFetchAt    *time.Time `json:"last_fetch_at"`
	LastFetchError string     `json:"last_fetch_error" gorm:"type:varchar(512)"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (UserExtraLink) TableName() string { return "nodemgt_user_extra_links" }

type Certificate struct {
	ID          string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	NodeUUID    string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Domain      string     `json:"domain" gorm:"type:varchar(253);not null"`
	Source      string     `json:"source" gorm:"type:varchar(16);not null;default:'acme'"`
	Issuer      string     `json:"issuer" gorm:"type:varchar(64);not null;default:''"`
	Fingerprint string     `json:"fingerprint" gorm:"type:varchar(128)"`
	NotAfter    *time.Time `json:"not_after"`
	CertPath    string     `json:"cert_path" gorm:"type:varchar(512)"`
	KeyPath     string     `json:"key_path" gorm:"type:varchar(512)"`
	ChainPEM    string     `json:"chain_pem,omitempty" gorm:"type:longtext"`
	Status      string     `json:"status" gorm:"type:varchar(16);not null;default:'pending'"`
	LastError   string     `json:"last_error" gorm:"type:varchar(512)"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (Certificate) TableName() string { return "nodemgt_certs" }

type ControlCommand struct {
	ID          string     `json:"id" gorm:"type:varchar(36);primaryKey"`
	OperationID string     `json:"operation_id" gorm:"type:varchar(64);uniqueIndex;not null"`
	NodeUUID    string     `json:"node_uuid" gorm:"type:varchar(36);index;not null"`
	Kind        string     `json:"kind" gorm:"type:varchar(32);not null"`
	PayloadJSON string     `json:"payload_json" gorm:"type:longtext"`
	Status      string     `json:"status" gorm:"type:varchar(16);not null;default:'pending'"`
	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	LastError   string     `json:"last_error" gorm:"type:varchar(512)"`
	AckedAt     *time.Time `json:"acked_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (ControlCommand) TableName() string { return "nodemgt_control_commands" }

type AuditEvent struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Actor     string    `json:"actor" gorm:"type:varchar(100);not null"`
	Action    string    `json:"action" gorm:"type:varchar(64);not null"`
	Target    string    `json:"target" gorm:"type:varchar(128)"`
	Detail    string    `json:"detail" gorm:"type:longtext"`
	CreatedAt time.Time `json:"created_at"`
}

func (AuditEvent) TableName() string { return "nodemgt_audit_events" }

type Setting struct {
	Key       string    `json:"key" gorm:"type:varchar(64);primaryKey"`
	Value     string    `json:"value" gorm:"type:longtext"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Setting) TableName() string { return "nodemgt_settings" }

type UserIP struct {
	ID        string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID    string    `json:"user_id" gorm:"type:varchar(36);uniqueIndex:uid_ip_node;not null"`
	IP        string    `json:"ip" gorm:"type:varchar(64);uniqueIndex:uid_ip_node;not null"`
	NodeUUID  string    `json:"node_uuid" gorm:"type:varchar(36);uniqueIndex:uid_ip_node;index;not null"`
	SeenAt    time.Time `json:"seen_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (UserIP) TableName() string { return "nodemgt_user_ips" }

func All() []any {
	return []any{
		&Inbound{},
		&Outbound{},
		&Route{},
		&Grant{},
		&NodeUser{},
		&Credential{},
		&Plan{},
		&Assignment{},
		&QuotaLedger{},
		&QuotaLease{},
		&Subscription{},
		&UserExtraLink{},
		&Certificate{},
		&ControlCommand{},
		&AuditEvent{},
		&Setting{},
		&UserIP{},
	}
}
