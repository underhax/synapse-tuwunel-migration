package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

func makeAccount(userID, synPass, synToken, tuwPass, recKey string, admin bool) AccountConfig {
	var acc AccountConfig
	acc.UserID = userID
	acc.SynapsePassword = synPass
	acc.SynapseAccessToken = synToken
	acc.TuwunelPassword = tuwPass
	acc.RecoveryKey = recKey
	acc.Admin = admin
	return acc
}

func buildSampleConfig(dir string) *Config {
	return &Config{
		ServerName:            "alpha.example.com",
		SynapseURL:            "https://synapse.alpha.example.com/",
		TuwunelURL:            "https://tuwunel.alpha.example.com/",
		TuwunelSharedSecret:   "example-shared-secret",
		DataDir:               filepath.Join(dir, "dump"),
		LocalRoomVersion:      "12",
		ReplaySingleUserNotes: true,
		Accounts: []AccountConfig{
			makeAccount("@alice:alpha.example.com", "example-1", "", "example-2", "example-rec-1", true),
			makeAccount("@bob:alpha.example.com", "", "example-3", "example-4", "example-rec-2", false),
		},
	}
}

func writePermFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		wantErr error
		raw     string
		want    Mode
	}{
		{raw: "prepare-signing-key", want: ModePrepareSigningKey},
		{raw: "export", want: ModeExport},
		{raw: "  import-local  ", want: ModeImportLocal},
		{raw: "federate-sync", want: ModeFederateSync},
		{raw: "cleanup", want: ModeCleanup},
		{raw: "unknown", wantErr: ErrInvalidMode},
		{raw: "", wantErr: ErrInvalidMode},
	}

	for _, tc := range tests {
		got, err := ParseMode(tc.raw)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("ParseMode(%q) err = %v, want %v", tc.raw, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestLoadSuccessAndPermissions(t *testing.T) {
	dir := t.TempDir()
	sample := buildSampleConfig(dir)
	sample.LocalRoomVersion = ""
	sample.Accounts[0].ExistsOnTuwunel = true

	raw, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	tests := []struct {
		name string
		perm os.FileMode
	}{
		{name: "read-only 0400", perm: 0o400},
		{name: "owner rw 0600", perm: 0o600},
	}

	for _, tc := range tests {
		cfgPath := filepath.Join(dir, "cfg_"+tc.name+".json")
		writePermFile(t, cfgPath, raw, tc.perm)

		loaded, loadErr := Load(cfgPath)
		if loadErr != nil {
			t.Fatalf("Load(%s) unexpected error: %v", tc.name, loadErr)
		}
		if loaded.SynapseURL != "https://synapse.alpha.example.com" {
			t.Errorf("SynapseURL = %q, expected trimmed trailing slash", loaded.SynapseURL)
		}
		if loaded.TuwunelURL != "https://tuwunel.alpha.example.com" {
			t.Errorf("TuwunelURL = %q, expected trimmed trailing slash", loaded.TuwunelURL)
		}
		if loaded.LocalRoomVersion != defaultLocalRoomVersion {
			t.Errorf("LocalRoomVersion = %q, want %q", loaded.LocalRoomVersion, defaultLocalRoomVersion)
		}
		if loaded.Accounts[0].Localpart() != "alice" {
			t.Errorf("Localpart() = %q, want alice", loaded.Accounts[0].Localpart())
		}
		if !loaded.Accounts[0].ExistsOnTuwunel {
			t.Errorf("Accounts[0].ExistsOnTuwunel = false, want true")
		}
		if loaded.Accounts[1].ExistsOnTuwunel {
			t.Errorf("Accounts[1].ExistsOnTuwunel = true, want false")
		}

		set := loaded.AllowlistedUserSet()
		if len(set) != 2 {
			t.Errorf("AllowlistedUserSet len = %d, want 2", len(set))
		}
		if _, ok := set["@bob:alpha.example.com"]; !ok {
			t.Errorf("missing @bob:alpha.example.com in AllowlistedUserSet")
		}
	}
}

func TestLoadFailures(t *testing.T) {
	dir := t.TempDir()
	valid := buildSampleConfig(dir)
	validBytes, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal valid: %v", err)
	}

	permPath := filepath.Join(dir, "insecure.json")
	writePermFile(t, permPath, validBytes, 0o200)

	unknownFieldPath := filepath.Join(dir, "unknown.json")
	writePermFile(t, unknownFieldPath, []byte(`{"unknown_field":true}`), 0o600)

	trailingPath := filepath.Join(dir, "trailing.json")
	trailingData := append(append([]byte{}, validBytes...), []byte(` {"extra":1}`)...)
	writePermFile(t, trailingPath, trailingData, 0o600)

	badValidationPath := filepath.Join(dir, "bad_val.json")
	badCfg := buildSampleConfig(dir)
	badCfg.DataDir = ""
	badBytes, marshalErr := json.Marshal(badCfg)
	if marshalErr != nil {
		t.Fatalf("marshal badCfg: %v", marshalErr)
	}
	writePermFile(t, badValidationPath, badBytes, 0o600)

	tests := []struct {
		wantErr error
		name    string
		path    string
		anyErr  bool
	}{
		{name: "missing file", path: filepath.Join(dir, "missing.json"), wantErr: os.ErrNotExist},
		{name: "insecure permissions", path: permPath, wantErr: validator.ErrInsecurePermission},
		{name: "unknown JSON field", path: unknownFieldPath, anyErr: true},
		{name: "trailing JSON data", path: trailingPath, wantErr: ErrTrailingJSON},
		{name: "validation failure", path: badValidationPath, wantErr: ErrEmptyDataDir},
	}

	for _, tc := range tests {
		_, loadErr := Load(tc.path)
		if tc.anyErr {
			if loadErr == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
			continue
		}
		if !errors.Is(loadErr, tc.wantErr) {
			t.Errorf("%s: got err %v, want %v", tc.name, loadErr, tc.wantErr)
		}
	}
}

func TestLoadReadFileErrors(t *testing.T) {
	if _, err := defaultReadFile(filepath.Join(t.TempDir(), "nonexistent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaultReadFile missing err = %v, want os.ErrNotExist", err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "valid_perm.json")
	writePermFile(t, cfgPath, []byte(`{}`), 0o400)

	origReadFile := readFile
	t.Cleanup(func() {
		readFile = origReadFile
	})

	sentinel := errors.New("injected read failure")
	readFile = func(string) ([]byte, error) {
		return nil, sentinel
	}

	if _, err := Load(cfgPath); !errors.Is(err, sentinel) {
		t.Errorf("Load readFile err = %v, want %v", err, sentinel)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		mutate  func(*Config)
		wantErr error
		name    string
	}{
		{
			name:    "invalid server_name",
			mutate:  func(c *Config) { c.ServerName = "bad_host" },
			wantErr: validator.ErrInvalidDomain,
		},
		{
			name:    "invalid synapse_url",
			mutate:  func(c *Config) { c.SynapseURL = "ftp://synapse.beta.example.net" },
			wantErr: validator.ErrInvalidURL,
		},
		{
			name:    "invalid tuwunel_url",
			mutate:  func(c *Config) { c.TuwunelURL = "not-a-url" },
			wantErr: validator.ErrInvalidURL,
		},
		{
			name:    "empty data_dir",
			mutate:  func(c *Config) { c.DataDir = "   " },
			wantErr: ErrEmptyDataDir,
		},
		{
			name:    "no accounts",
			mutate:  func(c *Config) { c.Accounts = nil },
			wantErr: ErrNoAccounts,
		},
		{
			name:    "domain mismatch user_id",
			mutate:  func(c *Config) { c.Accounts[0].UserID = "@carol:gamma.example.org" },
			wantErr: validator.ErrUserDomainMismatch,
		},
		{
			name: "duplicate user_id",
			mutate: func(c *Config) {
				c.Accounts[1].UserID = c.Accounts[0].UserID
			},
			wantErr: ErrDuplicateAccount,
		},
	}

	for _, tc := range tests {
		cfg := buildSampleConfig(dir)
		tc.mutate(cfg)
		err := cfg.Validate()
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: Validate() err = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestValidateForMode(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		mutate  func(*Config)
		wantErr error
		name    string
		mode    Mode
	}{
		{
			name: "export valid",
			mode: ModeExport,
		},
		{
			name: "import-local valid",
			mode: ModeImportLocal,
		},
		{
			name: "federate-sync valid",
			mode: ModeFederateSync,
		},
		{
			name: "prepare-signing-key valid without secrets",
			mode: ModePrepareSigningKey,
			mutate: func(c *Config) {
				c.Accounts[0].SynapsePassword = ""
				c.Accounts[0].SynapseAccessToken = ""
				c.Accounts[0].TuwunelPassword = ""
				c.Accounts[0].RecoveryKey = ""
			},
		},
		{
			name: "cleanup valid without secrets",
			mode: ModeCleanup,
			mutate: func(c *Config) {
				c.Accounts[0].SynapsePassword = ""
				c.Accounts[0].SynapseAccessToken = ""
				c.Accounts[0].TuwunelPassword = ""
				c.Accounts[0].RecoveryKey = ""
			},
		},
		{
			name:    "invalid mode",
			mode:    Mode("invalid"),
			wantErr: ErrInvalidMode,
		},
		{
			name:    "structural failure propagated",
			mode:    ModeExport,
			mutate:  func(c *Config) { c.Accounts = nil },
			wantErr: ErrNoAccounts,
		},
		{
			name: "export missing synapse auth",
			mode: ModeExport,
			mutate: func(c *Config) {
				c.Accounts[0].SynapsePassword = ""
				c.Accounts[0].SynapseAccessToken = ""
			},
			wantErr: ErrMissingSynapseAuth,
		},
		{
			name:    "export missing recovery key",
			mode:    ModeExport,
			mutate:  func(c *Config) { c.Accounts[0].RecoveryKey = "" },
			wantErr: ErrMissingRecoveryKey,
		},
		{
			name:    "import-local missing tuwunel password",
			mode:    ModeImportLocal,
			mutate:  func(c *Config) { c.Accounts[1].TuwunelPassword = "" },
			wantErr: ErrMissingTuwunelPass,
		},
		{
			name:    "federate-sync missing recovery key",
			mode:    ModeFederateSync,
			mutate:  func(c *Config) { c.Accounts[1].RecoveryKey = "" },
			wantErr: ErrMissingRecoveryKey,
		},
	}

	for _, tc := range tests {
		cfg := buildSampleConfig(dir)
		if tc.mutate != nil {
			tc.mutate(cfg)
		}
		err := cfg.ValidateForMode(tc.mode)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: ValidateForMode(%s) err = %v, want %v", tc.name, tc.mode, err, tc.wantErr)
		}
	}
}
