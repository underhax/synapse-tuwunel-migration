package signingkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/crypto/canonicaljson"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

type testServerIdentity struct {
	seedB64 string
	pubB64  string
	version string
	keyID   string
	rawLine string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
}

func generateTestServerIdentity(t *testing.T, version string, padded bool) *testServerIdentity {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("failed to extract Ed25519 public key")
	}
	var seedB64 string
	if padded {
		seedB64 = base64.StdEncoding.EncodeToString(seed)
	} else {
		seedB64 = base64.RawStdEncoding.EncodeToString(seed)
	}
	return &testServerIdentity{
		seedB64: seedB64,
		pubB64:  base64.RawStdEncoding.EncodeToString(pub),
		version: version,
		keyID:   "ed25519:" + version,
		rawLine: "ed25519 " + version + " " + seedB64,
		pub:     pub,
		priv:    priv,
	}
}

func signServerKeysPayload(t *testing.T, serverName string, ident *testServerIdentity, sigKeyID string, mutate func(map[string]any)) []byte {
	t.Helper()
	payload := map[string]any{
		"server_name":     serverName,
		"valid_until_ts":  int64(1800000000000),
		"verify_keys":     map[string]verifyKeyEntry{ident.keyID: {Key: ident.pubB64}},
		"old_verify_keys": map[string]any{},
	}
	canon, err := canonicaljson.Marshal(payload)
	if err != nil {
		t.Fatalf("canonicaljson.Marshal: %v", err)
	}
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(ident.priv, canon))
	if sigKeyID == "" {
		sigKeyID = ident.keyID
	}
	payload["signatures"] = map[string]any{
		serverName: map[string]string{
			sigKeyID: sig,
		},
	}
	if mutate != nil {
		mutate(payload)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return encoded
}

func decodeHexEscapedLiteral(t *testing.T, escaped string) []byte {
	t.Helper()
	if len(escaped)%4 != 0 {
		t.Fatalf("hex literal length %d not divisible by 4", len(escaped))
	}
	out := make([]byte, 0, len(escaped)/4)
	for i := 0; i < len(escaped); i += 4 {
		if escaped[i] != '\\' || escaped[i+1] != 'x' {
			t.Fatalf("invalid escape sequence at offset %d in %q", i, escaped[:min(len(escaped), i+8)])
		}
		v, err := strconv.ParseUint(escaped[i+2:i+4], 16, 8)
		if err != nil {
			t.Fatalf("parse hex byte %q: %v", escaped[i+2:i+4], err)
		}
		out = append(out, byte(v))
	}
	return out
}

func newPrepareWorkspace(t *testing.T, serverName string) (workDir string, store *dump.Store, cfg *config.Config, ident *testServerIdentity) {
	t.Helper()
	workDir = filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatalf("MkdirAll workspace: %v", err)
	}
	dumpDir := filepath.Join(workDir, "dump")
	var err error
	store, err = dump.Open(dumpDir)
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	ident = generateTestServerIdentity(t, "a_WS1", false)
	cfg = &config.Config{
		ServerName:       serverName,
		SynapseURL:       "https://synapse." + serverName,
		TuwunelURL:       "https://tuwunel." + serverName,
		DataDir:          dumpDir,
		LocalRoomVersion: "12",
		Accounts: []config.AccountConfig{
			{
				UserID:      "@alice:" + serverName,
				RecoveryKey: "EsTtestRecovery",
			},
		},
	}
	return workDir, store, cfg, ident
}

func TestParseSynapseSigningKey(t *testing.T) {
	t.Parallel()

	unpaddedIdent := generateTestServerIdentity(t, "a_Unpad1", false)
	paddedIdent := generateTestServerIdentity(t, "a_Pad2", true)

	parsedUnpadded, err := ParseSynapseSigningKey([]byte("# Synapse signing key\r\n\r\n  " + unpaddedIdent.rawLine + "  \r\n"))
	if err != nil {
		t.Fatalf("ParseSynapseSigningKey unpadded: %v", err)
	}
	if parsedUnpadded.Version != unpaddedIdent.version || parsedUnpadded.KeyID != unpaddedIdent.keyID || parsedUnpadded.PublicKeyBase64 != unpaddedIdent.pubB64 {
		t.Fatalf("unexpected parsed metadata: %+v", parsedUnpadded)
	}

	parsedPadded, err := ParseSynapseSigningKey([]byte(paddedIdent.rawLine))
	if err != nil {
		t.Fatalf("ParseSynapseSigningKey padded: %v", err)
	}
	if parsedPadded.PublicKeyBase64 != paddedIdent.pubB64 {
		t.Fatalf("padded pubkey mismatch: got %q want %q", parsedPadded.PublicKeyBase64, paddedIdent.pubB64)
	}
}

func TestBuildTuwunelImportTOML(t *testing.T) {
	t.Parallel()

	ident := generateTestServerIdentity(t, "a_TOML1", false)
	parsed, err := ParseSynapseSigningKey([]byte(ident.rawLine))
	if err != nil {
		t.Fatalf("ParseSynapseSigningKey: %v", err)
	}

	tomlStr, err := BuildTuwunelImportTOML(parsed)
	if err != nil {
		t.Fatalf("BuildTuwunelImportTOML: %v", err)
	}
	for _, want := range []string{
		"[global.admin]",
		"execute = ['query raw put global keypair ",
		"', 'server shutdown']",
		"execute_errors_ignore = false",
		"[global.admin.room]",
		"create = false",
	} {
		if !strings.Contains(tomlStr, want) {
			t.Fatalf("TOML missing %q:\n%s", want, tomlStr)
		}
	}

	_, afterPrefix, hasStart := strings.Cut(tomlStr, "'query raw put global keypair ")
	hexLiteral, _, hasEnd := strings.Cut(afterPrefix, "', 'server shutdown'")
	if !hasStart || !hasEnd {
		t.Fatalf("failed to isolate execute command literal:\n%s", tomlStr)
	}

	decodedVal := decodeHexEscapedLiteral(t, hexLiteral)
	sepIdx := bytes.IndexByte(decodedVal, 0xff)
	if sepIdx <= 0 {
		t.Fatalf("missing 0xFF separator in decoded RocksDB value")
	}
	if gotVer := string(decodedVal[:sepIdx]); gotVer != ident.version {
		t.Fatalf("decoded key version = %q, want %q", gotVer, ident.version)
	}
	parsedAny, pkcsErr := x509.ParsePKCS8PrivateKey(decodedVal[sepIdx+1:])
	if pkcsErr != nil {
		t.Fatalf("x509.ParsePKCS8PrivateKey: %v", pkcsErr)
	}
	parsedPriv, ok := parsedAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsedAny)
	}
	parsedPub, ok := parsedPriv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(parsedPub, ident.pub) {
		t.Fatalf("round-trip public key mismatch")
	}
}

func TestParseAndBuildSigningKeyErrors(t *testing.T) {
	t.Parallel()

	ident := generateTestServerIdentity(t, "a_Err1", false)
	otherIdent := generateTestServerIdentity(t, "a_Err2", true)
	tooLongVer := strings.Repeat("a", maxKeyVersionLen+1)

	invalidCases := []struct {
		wantErr error
		name    string
		raw     string
	}{
		{name: "empty input", raw: "  \n# only comment\n", wantErr: ErrInvalidSigningKey},
		{name: "multiple keys", raw: ident.rawLine + "\n" + otherIdent.rawLine, wantErr: ErrInvalidSigningKey},
		{name: "two fields", raw: "ed25519 a_OnlyTwo", wantErr: ErrInvalidSigningKey},
		{name: "four fields", raw: ident.rawLine + " extra", wantErr: ErrInvalidSigningKey},
		{name: "unsupported alg", raw: "rsa a_RSA " + ident.seedB64, wantErr: ErrUnsupportedKeyAlg},
		{name: "invalid version dash", raw: "ed25519 bad-ver " + ident.seedB64, wantErr: ErrInvalidSigningKey},
		{name: "invalid version length", raw: "ed25519 " + tooLongVer + " " + ident.seedB64, wantErr: ErrInvalidSigningKey},
		{name: "invalid base64", raw: "ed25519 a_BadB64 !!!not-base64!!!", wantErr: ErrInvalidSigningKey},
		{name: "short seed", raw: "ed25519 a_Short " + base64.RawStdEncoding.EncodeToString([]byte("short-seed")), wantErr: ErrInvalidSigningKey},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, parseErr := ParseSynapseSigningKey([]byte(tc.raw)); !errors.Is(parseErr, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", parseErr, tc.wantErr)
			}
		})
	}

	buildInvalidCases := []struct {
		parsed *ParsedKey
		name   string
	}{
		{name: "nil parsed key", parsed: nil},
		{name: "empty version", parsed: &ParsedKey{PKCS8DER: []byte{1}}},
		{name: "empty der", parsed: &ParsedKey{Version: "a_OK"}},
	}
	for _, tc := range buildInvalidCases {
		if _, bErr := BuildTuwunelImportTOML(tc.parsed); !errors.Is(bErr, ErrInvalidSigningKey) {
			t.Fatalf("%s: expected ErrInvalidSigningKey, got %v", tc.name, bErr)
		}
	}
}

func TestProbeTuwunelServerKeyAndState(t *testing.T) {
	t.Parallel()

	ident := generateTestServerIdentity(t, "a_Live1", false)
	otherIdent := generateTestServerIdentity(t, "a_Live2", false)
	domain := "probe.example.com"
	ctx := context.Background()

	metaCases := []struct {
		wantErr   error
		name      string
		server    string
		keyID     string
		pubB64    string
		body      []byte
		status    int
		wantRes   KeyProbeResult
		closeSrv  bool
		reqFed    bool
		withState bool
	}{
		{
			name:      "valid canonical signed server key response",
			server:    domain,
			keyID:     ident.keyID,
			pubB64:    ident.pubB64,
			status:    http.StatusOK,
			body:      signServerKeysPayload(t, domain, ident, "", nil),
			wantRes:   KeyProbeVerified,
			reqFed:    true,
			withState: true,
		},
		{
			name:    "federation disabled 403 M_FORBIDDEN allowed when optional",
			server:  domain,
			keyID:   ident.keyID,
			pubB64:  ident.pubB64,
			status:  http.StatusForbidden,
			body:    []byte(`{"errcode":"M_FORBIDDEN","error":"Federation is disabled."}`),
			wantRes: KeyProbeFederationDisabled,
			reqFed:  false,
		},
		{
			name:      "federation disabled 403 M_FORBIDDEN rejected when federation required",
			server:    domain,
			keyID:     ident.keyID,
			pubB64:    ident.pubB64,
			status:    http.StatusForbidden,
			body:      []byte(`{"errcode":"M_FORBIDDEN","error":"Federation is disabled."}`),
			wantErr:   ErrServerKeyUnavailable,
			reqFed:    true,
			withState: true,
		},
		{
			name:    "403 with non-forbidden errcode fails",
			server:  domain,
			keyID:   ident.keyID,
			pubB64:  ident.pubB64,
			status:  http.StatusForbidden,
			body:    []byte(`{"errcode":"M_UNKNOWN","error":"blocked"}`),
			wantErr: ErrServerKeyUnavailable,
		},
		{
			name:      "unexpected HTTP 500 fails",
			server:    domain,
			keyID:     ident.keyID,
			pubB64:    ident.pubB64,
			status:    http.StatusInternalServerError,
			body:      []byte(`boom`),
			wantErr:   ErrServerKeyUnavailable,
			withState: true,
		},
		{
			name:    "invalid JSON body on 200 fails",
			server:  domain,
			keyID:   ident.keyID,
			pubB64:  ident.pubB64,
			status:  http.StatusOK,
			body:    []byte(`{broken`),
			wantErr: ErrServerKeyMismatch,
		},
		{
			name:    "server_name mismatch fails",
			server:  domain,
			keyID:   ident.keyID,
			pubB64:  ident.pubB64,
			status:  http.StatusOK,
			body:    signServerKeysPayload(t, "wrong.example.net", ident, "", nil),
			wantErr: ErrServerKeyMismatch,
		},
		{
			name:    "missing expected key ID fails",
			server:  domain,
			keyID:   ident.keyID,
			pubB64:  ident.pubB64,
			status:  http.StatusOK,
			body:    signServerKeysPayload(t, domain, otherIdent, "", nil),
			wantErr: ErrServerKeyMismatch,
		},
		{
			name:   "public key mismatch for matching key ID fails",
			server: domain,
			keyID:  ident.keyID,
			pubB64: ident.pubB64,
			status: http.StatusOK,
			body: signServerKeysPayload(t, domain, ident, "", func(m map[string]any) {
				m["verify_keys"] = map[string]verifyKeyEntry{ident.keyID: {Key: otherIdent.pubB64}}
			}),
			wantErr: ErrServerKeyMismatch,
		},
		{
			name:   "missing signature fails",
			server: domain,
			keyID:  ident.keyID,
			pubB64: ident.pubB64,
			status: http.StatusOK,
			body: signServerKeysPayload(t, domain, ident, "", func(m map[string]any) {
				delete(m, "signatures")
			}),
			wantErr: ErrServerKeySigInvalid,
		},
		{
			name:   "wrong signer private key returns invalid signature",
			server: domain,
			keyID:  ident.keyID,
			pubB64: ident.pubB64,
			status: http.StatusOK,
			body: signServerKeysPayload(t, domain, otherIdent, ident.keyID, func(m map[string]any) {
				m["verify_keys"] = map[string]verifyKeyEntry{ident.keyID: {Key: ident.pubB64}}
			}),
			wantErr: ErrServerKeySigInvalid,
		},
		{
			name:     "transport failure on closed server returns unavailable",
			server:   domain,
			keyID:    ident.keyID,
			pubB64:   ident.pubB64,
			closeSrv: true,
			wantErr:  ErrServerKeyUnavailable,
		},
	}

	for _, tc := range metaCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != serverKeyEndpointPath {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if _, err := w.Write(tc.body); err != nil {
					t.Fatalf("write response: %v", err)
				}
			}))
			url := srv.URL
			if tc.closeSrv {
				srv.Close()
			} else {
				defer srv.Close()
			}

			if tc.withState {
				gotRes, sErr := VerifyServerKeyState(ctx, srv.Client(), url, tc.server, &dump.ManifestState{
					ServerName:             tc.server,
					ServerSigningKeyID:     tc.keyID,
					ServerSigningPublicKey: tc.pubB64,
				}, tc.reqFed)
				assertServerKeyProbeOutcome(t, "VerifyServerKeyState", tc.wantErr, gotRes, tc.wantRes, sErr)
				return
			}

			res, err := ProbeTuwunelServerKey(ctx, srv.Client(), url, tc.server, tc.keyID, tc.pubB64)
			assertServerKeyProbeOutcome(t, "ProbeTuwunelServerKey", tc.wantErr, res, tc.wantRes, err)
		})
	}

	badInputCases := []struct {
		name   string
		server string
		keyID  string
		pubB64 string
	}{
		{name: "missing ed25519 prefix", server: domain, keyID: "a_BadPrefix", pubB64: ident.pubB64},
		{name: "invalid version chars", server: domain, keyID: "ed25519:bad-ver", pubB64: ident.pubB64},
		{name: "empty pubkey", server: domain, keyID: ident.keyID, pubB64: ""},
		{name: "empty serverName", server: "", keyID: ident.keyID, pubB64: ident.pubB64},
	}
	for _, tc := range badInputCases {
		if _, err := ProbeTuwunelServerKey(ctx, nil, "https://unused.example.com", tc.server, tc.keyID, tc.pubB64); !errors.Is(err, ErrInvalidSigningKey) {
			t.Fatalf("%s: err=%v, want %v", tc.name, err, ErrInvalidSigningKey)
		}
	}

	for _, tc := range []struct {
		manifest *dump.ManifestState
		name     string
	}{
		{name: "nil manifest", manifest: nil},
		{name: "missing key id", manifest: &dump.ManifestState{ServerSigningPublicKey: ident.pubB64}},
		{name: "missing pubkey", manifest: &dump.ManifestState{ServerSigningKeyID: ident.keyID}},
	} {
		if _, err := VerifyServerKeyState(ctx, nil, "https://unused.example.com", domain, tc.manifest, false); !errors.Is(err, ErrMissingServerKeyState) {
			t.Fatalf("%s: err=%v, want %v", tc.name, err, ErrMissingServerKeyState)
		}
	}
}

func TestRunPrepareSigningKeyInitialWrites(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workDir, store, cfg, ident := newPrepareWorkspace(t, "prepare.example.com")
	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)

	if err := os.WriteFile(keyPath, []byte(ident.rawLine+"\n"), 0o400); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	if err := Run(ctx, workDir, cfg, store, nil); err != nil {
		t.Fatalf("Run before export failed: %v", err)
	}

	tomlInfo, err := os.Stat(store.SigningKeyTOMLPath())
	if err != nil {
		t.Fatalf("Stat TOML drop-in: %v", err)
	}
	if perm := tomlInfo.Mode().Perm(); perm != 0o400 {
		t.Fatalf("TOML drop-in permissions = %04o, want 0400", perm)
	}
	if valErr := store.ValidateSigningKeyTOML(); valErr != nil {
		t.Fatalf("ValidateSigningKeyTOML: %v", valErr)
	}

	manifest, err := store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if manifest.Phase != dump.PhaseSigningKeyPrepared || manifest.ServerSigningKeyID != ident.keyID || manifest.ServerSigningPublicKey != ident.pubB64 {
		t.Fatalf("unexpected initial manifest: %+v", manifest)
	}
}

func TestRunPrepareSigningKeyPreservesManifest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workDir, store, cfg, ident := newPrepareWorkspace(t, "rerun.example.com")
	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)
	if err := os.WriteFile(keyPath, []byte(ident.rawLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	if writeErr := store.WriteManifest(&dump.ManifestState{
		LocalRoomMap:     map[string]string{"!old:rerun.example.com": "!new:rerun.example.com"},
		ProvisionedUsers: map[string]bool{"@alice:rerun.example.com": true},
		ServerName:       cfg.ServerName,
		LocalRoomVersion: "12",
		ExportedAt:       "2026-11-10T00:00:00Z",
		Phase:            dump.PhaseExported,
	}); writeErr != nil {
		t.Fatalf("WriteManifest exported: %v", writeErr)
	}

	log := zerolog.Nop()
	if rerunErr := Run(ctx, workDir, cfg, store, &log); rerunErr != nil {
		t.Fatalf("Run over existing export with 0600 key failed: %v", rerunErr)
	}

	after, err := store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest after rerun: %v", err)
	}
	if after.Phase != dump.PhaseExported || after.LocalRoomMap["!old:rerun.example.com"] != "!new:rerun.example.com" || !after.ProvisionedUsers["@alice:rerun.example.com"] || after.ExportedAt != "2026-11-10T00:00:00Z" {
		t.Fatalf("existing export manifest fields lost: %+v", after)
	}
	if after.ServerSigningKeyID != ident.keyID || after.ServerSigningPublicKey != ident.pubB64 {
		t.Fatalf("signing key fields not preserved/updated: %+v", after)
	}
}

func TestRunPrepareSigningKeyFillsBlankManifestDefaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workDir, store, cfg, ident := newPrepareWorkspace(t, "blank.example.org")
	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)
	if err := os.WriteFile(keyPath, []byte(ident.rawLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	if blankErr := store.WriteManifest(&dump.ManifestState{}); blankErr != nil {
		t.Fatalf("WriteManifest blank: %v", blankErr)
	}
	log := zerolog.Nop()
	if blankRunErr := Run(ctx, workDir, cfg, store, &log); blankRunErr != nil {
		t.Fatalf("Run over blank manifest failed: %v", blankRunErr)
	}
	filled, err := store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest filled: %v", err)
	}
	if filled.Phase != dump.PhaseSigningKeyPrepared || filled.ServerName != cfg.ServerName || filled.LocalRoomVersion != cfg.LocalRoomVersion {
		t.Fatalf("blank manifest defaults not populated: %+v", filled)
	}
}

func TestRunPrepareSigningKeyValidationErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workDir, store, cfg, _ := newPrepareWorkspace(t, "valerr.example.net")

	if err := Run(ctx, workDir, nil, store, nil); !errors.Is(err, ErrNilConfig) {
		t.Fatalf("Run(nil cfg) = %v, want %v", err, ErrNilConfig)
	}
	if err := Run(ctx, workDir, cfg, nil, nil); !errors.Is(err, ErrNilStore) {
		t.Fatalf("Run(nil store) = %v, want %v", err, ErrNilStore)
	}

	badCfg := *cfg
	badCfg.ServerName = ""
	if err := Run(ctx, workDir, &badCfg, store, nil); err == nil {
		t.Fatal("expected ValidateForMode error on invalid config")
	}

	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key file err = %v, want os.ErrNotExist", err)
	}

	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)
	if err := os.WriteFile(keyPath, []byte("malformed-key-line\n"), 0o400); err != nil {
		t.Fatalf("WriteFile malformed key: %v", err)
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("malformed key err = %v, want ErrInvalidSigningKey", err)
	}
}

func assertServerKeyProbeOutcome(t *testing.T, fnName string, wantErr error, gotRes, wantRes KeyProbeResult, gotErr error) {
	t.Helper()
	if wantErr != nil {
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("%s err=%v, want %v", fnName, gotErr, wantErr)
		}
		return
	}
	if gotErr != nil || gotRes != wantRes {
		t.Fatalf("%s = (%v, %v), want (%v, nil)", fnName, gotRes, gotErr, wantRes)
	}
}

func TestRunPrepareSigningKeyFileAndManifestErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workDir, store, cfg, ident := newPrepareWorkspace(t, "err.example.net")
	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)

	if err := os.WriteFile(keyPath, []byte(ident.rawLine), 0o200); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	if err := os.Chmod(keyPath, 0o200); err != nil {
		t.Fatalf("Chmod key 0200: %v", err)
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, validator.ErrInsecurePermission) {
		t.Fatalf("insecure key mode err = %v, want ErrInsecurePermission", err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("Remove key: %v", err)
	}
	outsideFile := filepath.Join(t.TempDir(), "outside.signing.key")
	if err := os.WriteFile(outsideFile, []byte(ident.rawLine), 0o400); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	if err := os.Symlink(outsideFile, keyPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, validator.ErrPathOutsideWorkspace) {
		t.Fatalf("symlink escape err = %v, want ErrPathOutsideWorkspace", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(ident.rawLine), 0o400); err != nil {
		t.Fatalf("WriteFile valid key: %v", err)
	}

	if err := os.WriteFile(filepath.Join(store.Root(), "manifest_state.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt manifest: %v", err)
	}
	if err := Run(ctx, workDir, cfg, store, nil); err == nil {
		t.Fatal("expected corrupt manifest_state.json error")
	}
}

func TestSigningKeyHookErrors(t *testing.T) {
	ctx := context.Background()
	workDir, store, cfg, ident := newPrepareWorkspace(t, "hooks.example.org")
	keyPath := filepath.Join(workDir, SynapseSigningKeyFile)
	if err := os.WriteFile(keyPath, []byte(ident.rawLine), 0o400); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	if _, err := defaultEncodePKCS8DER("not-a-private-key"); err == nil {
		t.Fatal("expected defaultEncodePKCS8DER error on string input")
	}
	if _, err := defaultReadFileBytes(filepath.Join(workDir, "absent.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaultReadFileBytes missing err = %v", err)
	}
	if err := defaultWriteSigningKeyTOML(&dump.Store{}, []byte("x")); err == nil {
		t.Fatal("expected defaultWriteSigningKeyTOML error on uninitialized store")
	}
	if err := defaultWriteManifest(&dump.Store{}, &dump.ManifestState{}); err == nil {
		t.Fatal("expected defaultWriteManifest error on uninitialized store")
	}

	origPKCS8 := encodePKCS8DER
	origRead := readFileBytes
	origTOML := writeSigningKeyTOML
	origManifest := writeManifest
	t.Cleanup(func() {
		encodePKCS8DER = origPKCS8
		readFileBytes = origRead
		writeSigningKeyTOML = origTOML
		writeManifest = origManifest
	})

	sentinel := errors.New("injected signingkey hook failure")
	encodePKCS8DER = func(any) ([]byte, error) {
		return nil, sentinel
	}
	if _, err := ParseSynapseSigningKey([]byte(ident.rawLine)); !errors.Is(err, sentinel) {
		t.Fatalf("encodePKCS8DER hook err = %v, want %v", err, sentinel)
	}
	encodePKCS8DER = origPKCS8

	readFileBytes = func(string) ([]byte, error) {
		return nil, sentinel
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, sentinel) {
		t.Fatalf("readFileBytes hook err = %v, want %v", err, sentinel)
	}
	readFileBytes = origRead

	writeSigningKeyTOML = func(*dump.Store, []byte) error {
		return sentinel
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, sentinel) {
		t.Fatalf("writeSigningKeyTOML hook err = %v, want %v", err, sentinel)
	}
	writeSigningKeyTOML = origTOML

	writeManifest = func(*dump.Store, *dump.ManifestState) error {
		return sentinel
	}
	if err := Run(ctx, workDir, cfg, store, nil); !errors.Is(err, sentinel) {
		t.Fatalf("writeManifest hook err = %v, want %v", err, sentinel)
	}
}
