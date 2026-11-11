// Package config loads and validates the migration manifest with strict file permissions.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

const defaultLocalRoomVersion = "12"

func defaultReadFile(name string) ([]byte, error) {
	cleanPath := filepath.Clean(name)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", cleanPath, err)
	}
	return data, nil
}

var readFile = defaultReadFile

// Mode selects which phase of the Synapse-to-Tuwunel migration pipeline executes.
type Mode string

// Supported CLI migration execution phases ordered along the blue-green cutover sequence.
const (
	ModePrepareSigningKey Mode = "prepare-signing-key"
	ModeExport            Mode = "export"
	ModeImportLocal       Mode = "import-local"
	ModeFederateSync      Mode = "federate-sync"
	ModeCleanup           Mode = "cleanup"
)

// Validation sentinel errors returned when loading or validating migration configuration.
var (
	ErrEmptyDataDir       = errors.New("data_dir must not be empty")
	ErrNoAccounts         = errors.New("accounts list must contain at least one account")
	ErrDuplicateAccount   = errors.New("duplicate user_id in accounts list")
	ErrMissingRecoveryKey = errors.New("recovery_key must not be empty")
	ErrMissingSynapseAuth = errors.New("either synapse_password or synapse_access_token must be provided")
	ErrMissingTuwunelPass = errors.New("tuwunel_password must not be empty")
	ErrInvalidMode        = errors.New("unsupported migration mode")
	ErrTrailingJSON       = errors.New("unexpected trailing data after JSON configuration object")
)

// AccountConfig defines credentials and recovery metadata for a single Matrix account being migrated.
type AccountConfig struct {
	UserID             string `json:"user_id"`
	SynapsePassword    string `json:"synapse_password"`
	SynapseAccessToken string `json:"synapse_access_token"`
	TuwunelPassword    string `json:"tuwunel_password"`
	RecoveryKey        string `json:"recovery_key"`
	Admin              bool   `json:"admin"`
	ExistsOnTuwunel    bool   `json:"exists_on_tuwunel"`
}

// Localpart extracts the Matrix username component before the homeserver domain delimiter.
func (a *AccountConfig) Localpart() string {
	trimmed := strings.TrimPrefix(a.UserID, "@")
	localpart, _, _ := strings.Cut(trimmed, ":")
	return localpart
}

// Config captures the full migration manifest used across export, staging import, federation sync, and cleanup.
type Config struct {
	ServerName            string          `json:"server_name"`
	SynapseURL            string          `json:"synapse_url"`
	TuwunelURL            string          `json:"tuwunel_url"`
	TuwunelSharedSecret   string          `json:"tuwunel_shared_secret"`
	DataDir               string          `json:"data_dir"`
	LocalRoomVersion      string          `json:"local_room_version"`
	Accounts              []AccountConfig `json:"accounts"`
	ReplaySingleUserNotes bool            `json:"replay_single_user_notes"`
}

// ParseMode validates a CLI execution mode string against the supported cutover phases.
func ParseMode(raw string) (Mode, error) {
	mode := Mode(strings.TrimSpace(raw))
	switch mode {
	case ModePrepareSigningKey, ModeExport, ModeImportLocal, ModeFederateSync, ModeCleanup:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidMode, raw)
	}
}

// Load verifies strict file permissions, parses migration JSON without unknown fields, and validates structural invariants.
func Load(path string) (*Config, error) {
	cleanPath := filepath.Clean(path)
	if err := validator.ValidateFileMode(cleanPath, 0o400, 0o600); err != nil {
		return nil, fmt.Errorf("check config permissions: %w", err)
	}

	raw, err := readFile(cleanPath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config JSON: %w", err)
	}

	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingJSON
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate normalizes optional defaults and verifies structural integrity of server endpoints and accounts.
func (c *Config) Validate() error {
	c.ServerName = strings.TrimSpace(c.ServerName)
	c.SynapseURL = strings.TrimRight(strings.TrimSpace(c.SynapseURL), "/")
	c.TuwunelURL = strings.TrimRight(strings.TrimSpace(c.TuwunelURL), "/")
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.LocalRoomVersion = strings.TrimSpace(c.LocalRoomVersion)

	if err := validator.ValidateServerName(c.ServerName); err != nil {
		return fmt.Errorf("validate server_name: %w", err)
	}
	if err := validator.ValidateHTTPURL(c.SynapseURL); err != nil {
		return fmt.Errorf("validate synapse_url: %w", err)
	}
	if err := validator.ValidateHTTPURL(c.TuwunelURL); err != nil {
		return fmt.Errorf("validate tuwunel_url: %w", err)
	}
	if c.DataDir == "" {
		return ErrEmptyDataDir
	}
	c.DataDir = filepath.Clean(c.DataDir)

	if c.LocalRoomVersion == "" {
		c.LocalRoomVersion = defaultLocalRoomVersion
	}

	if len(c.Accounts) == 0 {
		return ErrNoAccounts
	}

	seen := make(map[string]struct{}, len(c.Accounts))
	for i := range c.Accounts {
		c.Accounts[i].UserID = strings.TrimSpace(c.Accounts[i].UserID)
		c.Accounts[i].RecoveryKey = strings.TrimSpace(c.Accounts[i].RecoveryKey)

		if err := validator.ValidateUserIDForServer(c.Accounts[i].UserID, c.ServerName); err != nil {
			return fmt.Errorf("validate accounts[%d].user_id: %w", i, err)
		}
		if _, dup := seen[c.Accounts[i].UserID]; dup {
			return fmt.Errorf("%w: %s", ErrDuplicateAccount, c.Accounts[i].UserID)
		}
		seen[c.Accounts[i].UserID] = struct{}{}
	}

	return nil
}

// ValidateForMode ensures credentials and recovery keys required by the selected migration phase are present.
func (c *Config) ValidateForMode(mode Mode) error {
	if _, err := ParseMode(string(mode)); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}

	for i := range c.Accounts {
		if err := validateAccountForMode(&c.Accounts[i], i, mode); err != nil {
			return err
		}
	}

	return nil
}

func validateAccountForMode(acc *AccountConfig, index int, mode Mode) error {
	switch mode {
	case ModeExport:
		if acc.SynapsePassword == "" && acc.SynapseAccessToken == "" {
			return fmt.Errorf("accounts[%d] (%s): %w", index, acc.UserID, ErrMissingSynapseAuth)
		}
		if acc.RecoveryKey == "" {
			return fmt.Errorf("accounts[%d] (%s): %w", index, acc.UserID, ErrMissingRecoveryKey)
		}
	case ModeImportLocal, ModeFederateSync:
		if acc.TuwunelPassword == "" {
			return fmt.Errorf("accounts[%d] (%s): %w", index, acc.UserID, ErrMissingTuwunelPass)
		}
		if acc.RecoveryKey == "" {
			return fmt.Errorf("accounts[%d] (%s): %w", index, acc.UserID, ErrMissingRecoveryKey)
		}
	case ModePrepareSigningKey, ModeCleanup:
		return nil
	}
	return nil
}

// AllowlistedUserSet builds a fast lookup table of local user IDs authorized for migration.
func (c *Config) AllowlistedUserSet() map[string]struct{} {
	set := make(map[string]struct{}, len(c.Accounts))
	for _, acc := range c.Accounts {
		set[acc.UserID] = struct{}{}
	}
	return set
}
