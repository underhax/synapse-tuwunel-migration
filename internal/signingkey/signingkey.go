// Package signingkey parses Synapse Ed25519 signing keys, builds Tuwunel database import drop-ins, and verifies live server key endpoints.
package signingkey

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

// SynapseSigningKeyFile names the fixed workspace copy of Synapse's signing key required by prepare-signing-key.
const SynapseSigningKeyFile = "synapse.signing.key"

const (
	serverKeyEndpointPath = "/_matrix/key/v2/server"
	keyVersionPrefix      = "ed25519:"
	maxKeyVersionLen      = 255
	hexAlphabet           = "0123456789abcdef"
)

// Sentinel errors returned during signing-key parsing, drop-in generation, and live Tuwunel verification.
var (
	ErrNilConfig             = errors.New("config must not be nil")
	ErrNilStore              = errors.New("dump store must not be nil")
	ErrInvalidSigningKey     = errors.New("invalid synapse signing key format")
	ErrUnsupportedKeyAlg     = errors.New("unsupported synapse signing key algorithm")
	ErrMissingServerKeyState = errors.New("manifest_state.json missing prepared server signing key metadata; run --mode prepare-signing-key")
	ErrServerKeyMismatch     = errors.New("tuwunel server signing key does not match prepared synapse key")
	ErrServerKeySigInvalid   = errors.New("tuwunel server signing key response signature verification failed")
	ErrServerKeyUnavailable  = errors.New("tuwunel server signing key endpoint returned unexpected status")
)

// KeyProbeResult describes the outcome of querying Tuwunel's public server key endpoint.
type KeyProbeResult int

// Possible outcomes from probing GET /_matrix/key/v2/server on Tuwunel.
const (
	KeyProbeVerified KeyProbeResult = iota + 1
	KeyProbeFederationDisabled
)

// ParsedKey holds the validated key version, public verify key, and PKCS#8 DER payload derived from Synapse.
type ParsedKey struct {
	Version         string
	KeyID           string
	PublicKeyBase64 string
	PKCS8DER        []byte
}

type verifyKeyEntry struct {
	Key string `json:"key"`
}

type serverKeyResponse struct {
	VerifyKeys map[string]verifyKeyEntry `json:"verify_keys"`
	ServerName string                    `json:"server_name"`
}

type matrixErrorBody struct {
	ErrCode string `json:"errcode"`
	Error   string `json:"error"`
}

func defaultEncodePKCS8DER(priv any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	return der, nil
}

func defaultReadFileBytes(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", cleanPath, err)
	}
	return data, nil
}

func defaultWriteSigningKeyTOML(store *dump.Store, data []byte) error {
	if err := store.WriteSigningKeyTOML(data); err != nil {
		return fmt.Errorf("write tuwunel key import drop-in: %w", err)
	}
	return nil
}

func defaultWriteManifest(store *dump.Store, state *dump.ManifestState) error {
	if err := store.WriteManifest(state); err != nil {
		return fmt.Errorf("write manifest_state.json: %w", err)
	}
	return nil
}

var (
	encodePKCS8DER      = defaultEncodePKCS8DER
	readFileBytes       = defaultReadFileBytes
	writeSigningKeyTOML = defaultWriteSigningKeyTOML
	writeManifest       = defaultWriteManifest
)

// Run parses the workspace synapse.signing.key, writes the 0400 Tuwunel import drop-in, and records public key metadata.
func Run(_ context.Context, workDir string, cfg *config.Config, store *dump.Store, log *zerolog.Logger) error {
	if cfg == nil {
		return ErrNilConfig
	}
	if store == nil {
		return ErrNilStore
	}
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}
	if err := cfg.ValidateForMode(config.ModePrepareSigningKey); err != nil {
		return fmt.Errorf("validate prepare-signing-key config: %w", err)
	}

	keyPath, err := validator.ConfinePath(workDir, SynapseSigningKeyFile, false)
	if err != nil {
		return fmt.Errorf("locate %s inside workspace: %w", SynapseSigningKeyFile, err)
	}
	if modeErr := validator.ValidateFileMode(keyPath, 0o400, 0o600); modeErr != nil {
		return fmt.Errorf("validate %s permissions: %w", SynapseSigningKeyFile, modeErr)
	}

	rawKey, err := readFileBytes(keyPath)
	if err != nil {
		return err
	}
	parsed, parseErr := ParseSynapseSigningKey(rawKey)
	clear(rawKey)
	if parseErr != nil {
		return parseErr
	}

	tomlContent := formatTuwunelImportTOML(parsed.Version, parsed.PKCS8DER)
	clear(parsed.PKCS8DER)
	tomlBytes := []byte(tomlContent)
	writeErr := writeSigningKeyTOML(store, tomlBytes)
	clear(tomlBytes)
	if writeErr != nil {
		return writeErr
	}

	manifest, err := loadOrInitManifest(cfg, store)
	if err != nil {
		return err
	}
	manifest.ServerSigningKeyID = parsed.KeyID
	manifest.ServerSigningPublicKey = parsed.PublicKeyBase64

	if err := writeManifest(store, manifest); err != nil {
		return err
	}

	log.Info().
		Str("server_signing_key_id", parsed.KeyID).
		Str("tuwunel_import_toml", store.SigningKeyTOMLPath()).
		Msg("Prepared Tuwunel server signing key import drop-in")

	return nil
}

// ParseSynapseSigningKey decodes a single Synapse ed25519 signing key record into PKCS#8 DER and base64 verify key form.
func ParseSynapseSigningKey(raw []byte) (*ParsedKey, error) {
	var keyLine string
	found := false

	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if found {
			return nil, fmt.Errorf("%w: expected exactly one key entry", ErrInvalidSigningKey)
		}
		keyLine = trimmed
		found = true
	}

	if !found {
		return nil, fmt.Errorf("%w: missing signing key entry", ErrInvalidSigningKey)
	}

	fields := strings.Fields(keyLine)
	if len(fields) != 3 {
		return nil, fmt.Errorf("%w: expected 3 whitespace-separated fields", ErrInvalidSigningKey)
	}
	if fields[0] != "ed25519" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyAlg, fields[0])
	}
	version := fields[1]
	if !isValidKeyVersion(version) {
		return nil, fmt.Errorf("%w: invalid key version %q", ErrInvalidSigningKey, version)
	}

	seed, decErr := decodeBase64Seed(fields[2])
	if decErr != nil {
		return nil, decErr
	}

	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)

	pubB64 := base64.RawStdEncoding.EncodeToString(priv[ed25519.SeedSize:])
	pkcs8DER, err := encodePKCS8DER(priv)
	clear(priv)
	if err != nil {
		return nil, err
	}

	return &ParsedKey{
		PKCS8DER:        pkcs8DER,
		Version:         version,
		KeyID:           keyVersionPrefix + version,
		PublicKeyBase64: pubB64,
	}, nil
}

func isValidKeyVersion(version string) bool {
	if version == "" || len(version) > maxKeyVersionLen {
		return false
	}
	for i := range len(version) {
		c := version[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigitOrUnderscore := (c >= '0' && c <= '9') || c == '_'
		if !isAlpha && !isDigitOrUnderscore {
			return false
		}
	}
	return true
}

func decodeBase64Seed(rawB64 string) ([]byte, error) {
	var (
		seed []byte
		err  error
	)
	if strings.Contains(rawB64, "=") {
		seed, err = base64.StdEncoding.DecodeString(rawB64)
	} else {
		seed, err = base64.RawStdEncoding.DecodeString(rawB64)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: decode base64 seed: %w", ErrInvalidSigningKey, err)
	}
	if len(seed) != ed25519.SeedSize {
		clear(seed)
		return nil, fmt.Errorf("%w: seed length %d bytes, want %d", ErrInvalidSigningKey, len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

// BuildTuwunelImportTOML encodes Tuwunel's global.keypair RocksDB value into a one-shot maintenance TOML drop-in.
func BuildTuwunelImportTOML(parsed *ParsedKey) (string, error) {
	if parsed == nil || !isValidKeyVersion(parsed.Version) || len(parsed.PKCS8DER) == 0 {
		return "", fmt.Errorf("%w: incomplete parsed key", ErrInvalidSigningKey)
	}
	return formatTuwunelImportTOML(parsed.Version, parsed.PKCS8DER), nil
}

func formatTuwunelImportTOML(version string, pkcs8DER []byte) string {
	rawVal := make([]byte, 0, len(version)+1+len(pkcs8DER))
	rawVal = append(rawVal, version...)
	rawVal = append(rawVal, 0xff)
	rawVal = append(rawVal, pkcs8DER...)

	var hexEscaped strings.Builder
	hexEscaped.Grow(len(rawVal) * 4)
	for _, b := range rawVal {
		hexEscaped.WriteString(`\x`)
		hexEscaped.WriteByte(hexAlphabet[b>>4])
		hexEscaped.WriteByte(hexAlphabet[b&0x0f])
	}
	clear(rawVal)

	var out strings.Builder
	out.WriteString("[global.admin]\n")
	out.WriteString("execute = ['query raw put global keypair ")
	out.WriteString(hexEscaped.String())
	out.WriteString("', 'server shutdown']\n")
	out.WriteString("execute_errors_ignore = false\n\n")
	out.WriteString("[global.admin.room]\n")
	out.WriteString("create = false\n")
	return out.String()
}

// VerifyServerKeyState ensures manifest key metadata exists and validates Tuwunel's live key endpoint against it.
func VerifyServerKeyState(
	ctx context.Context,
	httpClient *http.Client,
	tuwunelURL string,
	serverName string,
	manifest *dump.ManifestState,
	requireFederationEnabled bool,
) (KeyProbeResult, error) {
	if manifest == nil || manifest.ServerSigningKeyID == "" || manifest.ServerSigningPublicKey == "" {
		return 0, ErrMissingServerKeyState
	}

	res, err := ProbeTuwunelServerKey(
		ctx,
		httpClient,
		tuwunelURL,
		serverName,
		manifest.ServerSigningKeyID,
		manifest.ServerSigningPublicKey,
	)
	if err != nil {
		return 0, err
	}
	if requireFederationEnabled && res == KeyProbeFederationDisabled {
		return res, fmt.Errorf("%w: Tuwunel returned 403 M_FORBIDDEN; enable federation before running federate-sync", ErrServerKeyUnavailable)
	}
	return res, nil
}

// ProbeTuwunelServerKey queries GET /_matrix/key/v2/server and cryptographically verifies the response against the expected key.
func ProbeTuwunelServerKey(
	ctx context.Context,
	httpClient *http.Client,
	tuwunelURL string,
	serverName string,
	expectedKeyID string,
	expectedPubBase64 string,
) (KeyProbeResult, error) {
	keyVersion, ok := strings.CutPrefix(expectedKeyID, keyVersionPrefix)
	if !ok || !isValidKeyVersion(keyVersion) || expectedPubBase64 == "" || serverName == "" {
		return 0, fmt.Errorf("%w: invalid expected key metadata", ErrInvalidSigningKey)
	}

	targetURL := strings.TrimRight(strings.TrimSpace(tuwunelURL), "/") + serverKeyEndpointPath
	rawBody, statusCode, err := matrix.FetchBytes(ctx, httpClient, targetURL, "probe tuwunel server signing key")
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrServerKeyUnavailable, err)
	}

	if statusCode == http.StatusForbidden {
		var errBody matrixErrorBody
		if json.Unmarshal(rawBody, &errBody) == nil && errBody.ErrCode == mautrix.MForbidden.ErrCode {
			return KeyProbeFederationDisabled, nil
		}
		return 0, fmt.Errorf("%w: HTTP %d from %s", ErrServerKeyUnavailable, statusCode, serverKeyEndpointPath)
	}
	if statusCode != http.StatusOK {
		return 0, fmt.Errorf("%w: HTTP %d from %s", ErrServerKeyUnavailable, statusCode, serverKeyEndpointPath)
	}

	if err := verifyServerKeyPayload(rawBody, serverName, expectedKeyID, keyVersion, expectedPubBase64); err != nil {
		return 0, err
	}
	return KeyProbeVerified, nil
}

func verifyServerKeyPayload(rawBody []byte, serverName, expectedKeyID, keyVersion, expectedPubBase64 string) error {
	var parsed serverKeyResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return fmt.Errorf("%w: decode server key JSON: %w", ErrServerKeyMismatch, err)
	}
	if parsed.ServerName != serverName {
		return fmt.Errorf("%w: server_name=%q, want %q", ErrServerKeyMismatch, parsed.ServerName, serverName)
	}

	entry, hasKey := parsed.VerifyKeys[expectedKeyID]
	if !hasKey {
		return fmt.Errorf("%w: missing verify_key %s", ErrServerKeyMismatch, expectedKeyID)
	}
	if entry.Key != expectedPubBase64 {
		return fmt.Errorf("%w: verify_key %s does not match prepared Synapse key", ErrServerKeyMismatch, expectedKeyID)
	}

	verified, sigErr := signatures.VerifySignatureJSON(
		json.RawMessage(rawBody),
		id.UserID(serverName),
		keyVersion,
		id.Ed25519(expectedPubBase64),
	)
	if sigErr != nil {
		return fmt.Errorf("%w: %w", ErrServerKeySigInvalid, sigErr)
	}
	if !verified {
		return ErrServerKeySigInvalid
	}
	return nil
}

func loadOrInitManifest(cfg *config.Config, store *dump.Store) (*dump.ManifestState, error) {
	existing, err := store.ReadManifest()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read existing manifest_state.json: %w", err)
		}
		return &dump.ManifestState{
			LocalRoomMap:     make(map[string]string),
			ProvisionedUsers: make(map[string]bool),
			ServerName:       cfg.ServerName,
			LocalRoomVersion: cfg.LocalRoomVersion,
			Phase:            dump.PhaseSigningKeyPrepared,
		}, nil
	}

	if existing.LocalRoomMap == nil {
		existing.LocalRoomMap = make(map[string]string)
	}
	if existing.ProvisionedUsers == nil {
		existing.ProvisionedUsers = make(map[string]bool)
	}
	if existing.ServerName == "" {
		existing.ServerName = cfg.ServerName
	}
	if existing.LocalRoomVersion == "" {
		existing.LocalRoomVersion = cfg.LocalRoomVersion
	}
	if existing.Phase == "" {
		existing.Phase = dump.PhaseSigningKeyPrepared
	}
	return existing, nil
}
