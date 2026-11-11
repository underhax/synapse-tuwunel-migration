package dump

import "encoding/json"

// Phase names track cutover progress inside manifest_state.json.
const (
	PhaseSigningKeyPrepared = "signing_key_prepared"
	PhaseExported           = "exported"
	PhaseImportedLocal      = "imported_local"
	PhaseFederatedSync      = "federated_synced"
	PhaseCleanedUp          = "cleaned_up"
	RoomCategoryNotes       = "single_user_notes"
	RoomCategoryLocal       = "local_room"
	MaxMediaBytes           = 100 * 1024 * 1024
)

// ManifestState stores top-level export metadata, provisioned account flags, and local room mappings across phases.
type ManifestState struct {
	LocalRoomMap           map[string]string `json:"local_room_map"`
	ProvisionedUsers       map[string]bool   `json:"provisioned_users,omitempty"`
	ServerName             string            `json:"server_name"`
	LocalRoomVersion       string            `json:"local_room_version"`
	ExportedAt             string            `json:"exported_at"`
	Phase                  string            `json:"phase"`
	ServerSigningKeyID     string            `json:"server_signing_key_id,omitempty"`
	ServerSigningPublicKey string            `json:"server_signing_public_key,omitempty"`
}

// MediaRef identifies a locally cached binary asset saved under the content-addressed media directory.
type MediaRef struct {
	OriginalMXC string `json:"original_mxc"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	FileName    string `json:"filename,omitempty"`
	Size        int64  `json:"size"`
}

// EncryptionConfig records Matrix room encryption parameters to reapply on recreated local rooms.
type EncryptionConfig struct {
	Algorithm            string `json:"algorithm"`
	RotationPeriodMillis int64  `json:"rotation_period_ms,omitempty"`
	RotationPeriodMsgs   int    `json:"rotation_period_msgs,omitempty"`
}

// RetentionConfig preserves per-room message lifetime policies across migration.
type RetentionConfig struct {
	MaxLifetime *int64 `json:"max_lifetime,omitempty"`
	MinLifetime *int64 `json:"min_lifetime,omitempty"`
}

// PowerLevelsConfig captures transformed m.room.power_levels fields ready for Room Version 12 creation.
type PowerLevelsConfig struct {
	Users         map[string]int `json:"users,omitempty"`
	Events        map[string]int `json:"events,omitempty"`
	Notifications map[string]int `json:"notifications,omitempty"`
	UsersDefault  int            `json:"users_default"`
	EventsDefault int            `json:"events_default"`
	StateDefault  int            `json:"state_default"`
	Ban           int            `json:"ban"`
	Kick          int            `json:"kick"`
	Redact        int            `json:"redact"`
	Invite        int            `json:"invite"`
}

// SpaceChildEntry represents an m.space.child edge exported from a local Space room.
type SpaceChildEntry struct {
	ChildRoomID string   `json:"child_room_id"`
	Order       string   `json:"order,omitempty"`
	Via         []string `json:"via,omitempty"`
	Suggested   bool     `json:"suggested,omitempty"`
}

// NoteEntry stores a chronological plaintext or decrypted message from a single-user notes room for replay.
type NoteEntry struct {
	Media          *MediaRef       `json:"media,omitempty"`
	EventID        string          `json:"event_id"`
	MsgType        string          `json:"msgtype"`
	Body           string          `json:"body"`
	Format         string          `json:"format,omitempty"`
	FormattedBody  string          `json:"formatted_body,omitempty"`
	ReplyToEventID string          `json:"reply_to_event_id,omitempty"`
	Reactions      []string        `json:"reactions,omitempty"`
	Info           json.RawMessage `json:"info,omitempty"`
	Timestamp      int64           `json:"timestamp"`
}

// LocalRoom describes a deduplicated Category 3 or Category 4 room to recreate on Tuwunel.
type LocalRoom struct {
	Avatar             *MediaRef          `json:"avatar,omitempty"`
	Encryption         *EncryptionConfig  `json:"encryption,omitempty"`
	Retention          *RetentionConfig   `json:"retention,omitempty"`
	PowerLevels        *PowerLevelsConfig `json:"power_levels,omitempty"`
	OldRoomID          string             `json:"old_room_id"`
	Category           string             `json:"category"`
	RoomType           string             `json:"room_type,omitempty"`
	OriginalCreator    string             `json:"original_creator"`
	ChosenCreator      string             `json:"chosen_creator"`
	Name               string             `json:"name,omitempty"`
	Topic              string             `json:"topic,omitempty"`
	HistoryVisibility  string             `json:"history_visibility,omitempty"`
	JoinRule           string             `json:"join_rule,omitempty"`
	GuestAccess        string             `json:"guest_access,omitempty"`
	JoinedMembers      []string           `json:"joined_members"`
	AdditionalCreators []string           `json:"additional_creators,omitempty"`
	SpaceChildren      []SpaceChildEntry  `json:"space_children,omitempty"`
	Notes              []NoteEntry        `json:"notes,omitempty"`
	IsDirect           bool               `json:"is_direct,omitempty"`
}

// LocalRoomsData wraps deduplicated local rooms in rooms/local_rooms.json.
type LocalRoomsData struct {
	Rooms []LocalRoom `json:"rooms"`
}

// FederatedRoom captures a Category 2 federated room and prioritized candidate homeservers for rejoin.
type FederatedRoom struct {
	RoomID           string   `json:"room_id"`
	JoinedLocalUsers []string `json:"joined_local_users"`
	ViaServers       []string `json:"via_servers"`
}

// FederatedRoomsData wraps Category 2 federated rooms in rooms/federated_rooms.json.
type FederatedRoomsData struct {
	Rooms []FederatedRoom `json:"rooms"`
}

// IdentityData stores verified cross-signing seeds, the backup key, and verbatim SSSS account data payloads.
type IdentityData struct {
	RawSSSSAccountData    map[string]json.RawMessage `json:"raw_ssss_account_data"`
	UserID                string                     `json:"user_id"`
	DefaultSSSSKeyID      string                     `json:"default_ssss_key_id"`
	MasterPublicKey       string                     `json:"master_public_key"`
	SelfSigningPublicKey  string                     `json:"self_signing_public_key"`
	UserSigningPublicKey  string                     `json:"user_signing_public_key"`
	MegolmBackupPublicKey string                     `json:"megolm_backup_public_key"`
	KeyBackupVersion      string                     `json:"key_backup_version"`
	MasterSeed            []byte                     `json:"master_seed"`
	SelfSigningSeed       []byte                     `json:"self_signing_seed"`
	UserSigningSeed       []byte                     `json:"user_signing_seed"`
	MegolmBackupKey       []byte                     `json:"megolm_backup_key"`
}

// RoomKeySession mirrors an encrypted Megolm session record stored inside Matrix online key backups.
type RoomKeySession struct {
	SessionData       json.RawMessage `json:"session_data"`
	FirstMessageIndex int             `json:"first_message_index"`
	ForwardedCount    int             `json:"forwarded_count"`
	IsVerified        bool            `json:"is_verified"`
}

// RoomKeyBackupRoom groups backed-up encrypted Megolm sessions under a single room ID.
type RoomKeyBackupRoom struct {
	Sessions map[string]RoomKeySession `json:"sessions"`
}

// RoomKeysData stores filtered Megolm backup payloads per account in room_keys.json.
type RoomKeysData struct {
	Rooms  map[string]RoomKeyBackupRoom `json:"rooms"`
	UserID string                       `json:"user_id"`
}

// RoomTagEntry represents Matrix m.tag metadata such as favorite or lowpriority ordering.
type RoomTagEntry struct {
	Order *float64 `json:"order,omitempty"`
}

// ProfileData preserves user display metadata, filtered m.direct mappings, ignore lists, and per-room tags.
type ProfileData struct {
	Avatar       *MediaRef                          `json:"avatar,omitempty"`
	Direct       map[string][]string                `json:"direct,omitempty"`
	RoomTags     map[string]map[string]RoomTagEntry `json:"room_tags,omitempty"`
	UserID       string                             `json:"user_id"`
	DisplayName  string                             `json:"displayname,omitempty"`
	IgnoredUsers json.RawMessage                    `json:"ignored_users,omitempty"`
}

// TrustedContact records a user MasterKey verified to have been signed by the owner's user-signing key on Synapse.
type TrustedContact struct {
	UserID    string `json:"user_id"`
	MasterKey string `json:"master_key"`
	Local     bool   `json:"local"`
}

// TrustGraphData stores the snapshot of cross-signing contacts for a single local user.
type TrustGraphData struct {
	UserID   string           `json:"user_id"`
	Contacts []TrustedContact `json:"contacts"`
}

// SessionData records an active temporary device created on Tuwunel so cleanup can log it out reliably.
type SessionData struct {
	UserID        string `json:"user_id"`
	HomeserverURL string `json:"homeserver_url"`
	AccessToken   string `json:"access_token"`
	DeviceID      string `json:"device_id"`
}
