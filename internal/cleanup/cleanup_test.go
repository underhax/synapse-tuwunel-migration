package cleanup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
)

type tokenSession struct {
	userID   string
	deviceID string
}

type cleanupMockServer struct {
	server      *httptest.Server
	tokens      map[string]tokenSession
	forceStatus map[string]int
	mu          sync.Mutex
	logoutCalls int
}

func newCleanupMockServer(t *testing.T) *cleanupMockServer {
	t.Helper()
	m := &cleanupMockServer{
		tokens:      make(map[string]tokenSession),
		forceStatus: make(map[string]int),
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handleHTTP))
	t.Cleanup(m.server.Close)
	return m
}

func (m *cleanupMockServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	routeKey := r.Method + " " + r.URL.Path

	m.mu.Lock()
	if code, ok := m.forceStatus[routeKey]; ok {
		m.mu.Unlock()
		writeCleanupErr(w, code, "M_UNKNOWN", "forced")
		return
	}
	m.mu.Unlock()

	auth := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(auth, "Bearer ")
	if !found || token == "" {
		writeCleanupErr(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "missing")
		return
	}

	m.mu.Lock()
	sess, ok := m.tokens[token]
	m.mu.Unlock()
	if !ok {
		writeCleanupErr(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "expired")
		return
	}

	switch {
	case r.URL.Path == "/_matrix/client/v3/account/whoami" && r.Method == http.MethodGet:
		writeCleanupJSON(w, http.StatusOK, map[string]any{
			"user_id":   sess.userID,
			"device_id": sess.deviceID,
		})
	case r.URL.Path == "/_matrix/client/v3/logout" && r.Method == http.MethodPost:
		m.mu.Lock()
		delete(m.tokens, token)
		m.logoutCalls++
		m.mu.Unlock()
		writeCleanupJSON(w, http.StatusOK, map[string]any{})
	default:
		writeCleanupErr(w, http.StatusNotFound, "M_UNRECOGNIZED", "unknown")
	}
}

func writeCleanupErr(w http.ResponseWriter, status int, code, msg string) {
	writeCleanupJSON(w, status, map[string]any{"errcode": code, "error": msg})
}

func writeCleanupJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func makeCleanupConfig(serverName, tuwunelURL, dataDir string, userIDs ...string) *config.Config {
	accounts := make([]config.AccountConfig, 0, len(userIDs))
	for _, uid := range userIDs {
		accounts = append(accounts, config.AccountConfig{UserID: uid})
	}
	return &config.Config{
		ServerName: serverName,
		SynapseURL: "https://synapse." + serverName,
		TuwunelURL: tuwunelURL,
		DataDir:    dataDir,
		Accounts:   accounts,
	}
}

func TestRunHappyPathAndIdempotentRerun(t *testing.T) {
	t.Parallel()

	srv := newCleanupMockServer(t)
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}

	aliceID := "@alice:alpha.example"
	bobID := "@bob:alpha.example"
	carolID := "@carol:alpha.example"
	daveID := "@dave:alpha.example"

	srv.mu.Lock()
	srv.tokens["alice-active"] = tokenSession{userID: aliceID, deviceID: "DEV1"}
	srv.mu.Unlock()

	for _, s := range []dump.SessionData{
		{UserID: aliceID, HomeserverURL: srv.server.URL, AccessToken: "alice-active", DeviceID: "DEV1"},
		{UserID: bobID, HomeserverURL: srv.server.URL, AccessToken: "bob-revoked", DeviceID: "DEV2"},
		{UserID: daveID, HomeserverURL: srv.server.URL, AccessToken: "", DeviceID: "DEV4"},
	} {
		if writeErr := store.WriteSession(s.UserID, &s); writeErr != nil {
			t.Fatalf("WriteSession %s: %v", s.UserID, writeErr)
		}
	}

	if writeErr := store.WriteManifest(&dump.ManifestState{
		ServerName:       "alpha.example",
		LocalRoomVersion: "12",
		ExportedAt:       "2026-01-01T00:00:00Z",
		Phase:            dump.PhaseFederatedSync,
		LocalRoomMap:     map[string]string{"!old:alpha.example": "!new:alpha.example"},
		ProvisionedUsers: map[string]bool{aliceID: true},
	}); writeErr != nil {
		t.Fatalf("WriteManifest: %v", writeErr)
	}

	cfg := makeCleanupConfig("alpha.example", srv.server.URL, store.Root(), aliceID, bobID, carolID, daveID)
	var logBuf strings.Builder
	log := zerolog.New(&logBuf)

	if firstErr := Run(context.Background(), cfg, store, &log); firstErr != nil {
		t.Fatalf("first cleanup Run failed: %v", firstErr)
	}

	for _, uid := range []string{aliceID, bobID, carolID, daveID} {
		if _, readErr := store.ReadSession(uid); !errors.Is(readErr, os.ErrNotExist) {
			t.Fatalf("expected session.json removed for %s, got err=%v", uid, readErr)
		}
	}

	manifest, err := store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if manifest.Phase != dump.PhaseCleanedUp || manifest.LocalRoomMap["!old:alpha.example"] != "!new:alpha.example" {
		t.Fatalf("unexpected manifest state after cleanup: %+v", manifest)
	}

	srv.mu.Lock()
	firstLogouts := srv.logoutCalls
	remainingTokens := len(srv.tokens)
	srv.mu.Unlock()
	if firstLogouts != 1 || remainingTokens != 0 {
		t.Fatalf("expected 1 logout and 0 active tokens, got logouts=%d remaining=%d", firstLogouts, remainingTokens)
	}

	if secondErr := Run(context.Background(), cfg, store, nil); secondErr != nil {
		t.Fatalf("idempotent second cleanup Run failed: %v", secondErr)
	}

	srv.mu.Lock()
	secondLogouts := srv.logoutCalls
	srv.mu.Unlock()
	if secondLogouts != firstLogouts {
		t.Fatalf("expected zero additional logouts on rerun, got %d -> %d", firstLogouts, secondLogouts)
	}
}

func TestRunWithoutManifestAndLogoutNotFoundRace(t *testing.T) {
	t.Parallel()

	srv := newCleanupMockServer(t)
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}

	userID := "@alice:nomani.example.org"
	srv.mu.Lock()
	srv.tokens["tok-race"] = tokenSession{userID: userID, deviceID: "DEVRACE"}
	srv.forceStatus["POST /_matrix/client/v3/logout"] = http.StatusNotFound
	srv.mu.Unlock()

	if err := store.WriteSession(userID, &dump.SessionData{
		UserID:        userID,
		HomeserverURL: srv.server.URL,
		AccessToken:   "tok-race",
		DeviceID:      "DEVRACE",
	}); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}

	cfg := makeCleanupConfig("nomani.example.org", srv.server.URL, store.Root(), userID)
	if err := Run(context.Background(), cfg, store, nil); err != nil {
		t.Fatalf("expected cleanup without manifest to succeed, got: %v", err)
	}
	if _, err := store.ReadSession(userID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected session removed despite 404 logout race, got err=%v", err)
	}
	if _, err := store.ReadManifest(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing manifest to remain absent, got err=%v", err)
	}
}

func TestRunCleanupErrorBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup   func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config
		wantErr error
		name    string
		errText string
	}{
		{
			name: "nil config",
			setup: func(_ *testing.T, _ *cleanupMockServer, _ *dump.Store) *config.Config {
				return nil
			},
			wantErr: ErrNilConfig,
		},
		{
			name: "invalid config",
			setup: func(_ *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				return makeCleanupConfig("bad", srv.server.URL, store.Root(), "@a:bad")
			},
			errText: "validate cleanup config",
		},
		{
			name: "corrupt session.json",
			setup: func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				t.Helper()
				uid := "@alice:corrupt.example.net"
				accDir := filepath.Join(store.Root(), "accounts", uid)
				if err := os.MkdirAll(accDir, 0o700); err != nil {
					t.Fatalf("mkdir account: %v", err)
				}
				if err := os.WriteFile(filepath.Join(accDir, "session.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("write corrupt session: %v", err)
				}
				return makeCleanupConfig("corrupt.example.net", srv.server.URL, store.Root(), uid)
			},
			errText: "read session.json",
		},
		{
			name: "whoami server 500 error preserves session",
			setup: func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				t.Helper()
				uid := "@alice:whoami500.example.net"
				srv.mu.Lock()
				srv.forceStatus["GET /_matrix/client/v3/account/whoami"] = http.StatusInternalServerError
				srv.mu.Unlock()
				if err := store.WriteSession(uid, &dump.SessionData{UserID: uid, AccessToken: "tok"}); err != nil {
					t.Fatalf("WriteSession: %v", err)
				}
				return makeCleanupConfig("whoami500.example.net", srv.server.URL, store.Root(), uid)
			},
			errText: "verify session",
		},
		{
			name: "whoami mismatch error rejects spoofed token",
			setup: func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				t.Helper()
				uid := "@alice:mismatch.example.net"
				srv.mu.Lock()
				srv.tokens["wrong-owner-tok"] = tokenSession{userID: "@other:mismatch.example.net", deviceID: "DEV_SPOOF"}
				srv.mu.Unlock()
				if err := store.WriteSession(uid, &dump.SessionData{UserID: uid, AccessToken: "wrong-owner-tok"}); err != nil {
					t.Fatalf("WriteSession: %v", err)
				}
				return makeCleanupConfig("mismatch.example.net", srv.server.URL, store.Root(), uid)
			},
			wantErr: matrix.ErrWhoamiMismatch,
		},
		{
			name: "logout server 500 error fails cleanly",
			setup: func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				t.Helper()
				uid := "@alice:logout500.example.org"
				srv.mu.Lock()
				srv.tokens["tok-out500"] = tokenSession{userID: uid, deviceID: "DEV_OUT500"}
				srv.forceStatus["POST /_matrix/client/v3/logout"] = http.StatusInternalServerError
				srv.mu.Unlock()
				if err := store.WriteSession(uid, &dump.SessionData{UserID: uid, AccessToken: "tok-out500"}); err != nil {
					t.Fatalf("WriteSession: %v", err)
				}
				return makeCleanupConfig("logout500.example.org", srv.server.URL, store.Root(), uid)
			},
			errText: "logout temporary session",
		},
		{
			name: "corrupt manifest after session cleanup fails",
			setup: func(t *testing.T, srv *cleanupMockServer, store *dump.Store) *config.Config {
				t.Helper()
				if err := os.WriteFile(filepath.Join(store.Root(), "manifest_state.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("corrupt manifest: %v", err)
				}
				return makeCleanupConfig("badmani.example", srv.server.URL, store.Root(), "@alice:badmani.example")
			},
			errText: "read manifest_state.json after cleanup",
		},
	}

	ctx := context.Background()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newCleanupMockServer(t)
			store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
			if err != nil {
				t.Fatalf("dump.Open: %v", err)
			}
			cfg := tc.setup(t, srv, store)
			runErr := Run(ctx, cfg, store, nil)
			if runErr == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(runErr, tc.wantErr) {
				t.Fatalf("error = %v, want %v", runErr, tc.wantErr)
			}
			if tc.errText != "" && !strings.Contains(runErr.Error(), tc.errText) {
				t.Fatalf("error = %v, want substring %q", runErr, tc.errText)
			}
		})
	}

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		cfg := makeCleanupConfig("nilstore.example", "https://tuwunel.nilstore.example", "/tmp/x", "@a:nilstore.example")
		if err := Run(ctx, cfg, nil, nil); !errors.Is(err, ErrNilStore) {
			t.Fatalf("expected ErrNilStore, got %v", err)
		}
	})
}

func TestCleanupDefaultWrappersAndHooks(t *testing.T) {
	t.Run("defaultRemoveSession and defaultWriteManifest error wrappers", func(t *testing.T) {
		badStore, err := dump.Open(filepath.Join(t.TempDir(), "blocker_dump"))
		if err != nil {
			t.Fatalf("dump.Open: %v", err)
		}
		uid := "@blocker:wrap.example"
		if mkErr := os.MkdirAll(filepath.Join(badStore.Root(), "accounts", uid, "session.json", "nested"), 0o700); mkErr != nil {
			t.Fatalf("mkdir session blocker: %v", mkErr)
		}
		if err := defaultRemoveSession(badStore, uid); err == nil {
			t.Fatal("expected defaultRemoveSession error when target is non-empty directory")
		}
		if mkErr := os.MkdirAll(filepath.Join(badStore.Root(), "manifest_state.json", "nested"), 0o700); mkErr != nil {
			t.Fatalf("mkdir manifest blocker: %v", mkErr)
		}
		if err := defaultWriteManifest(badStore, &dump.ManifestState{}); err == nil {
			t.Fatal("expected defaultWriteManifest error when target is non-empty directory")
		}
	})

	t.Run("injected removeSession and writeManifest hooks", func(t *testing.T) {
		origRemove := removeSession
		origManifest := writeManifest
		t.Cleanup(func() {
			removeSession = origRemove
			writeManifest = origManifest
		})

		srv := newCleanupMockServer(t)
		store, err := dump.Open(filepath.Join(t.TempDir(), "hook_dump"))
		if err != nil {
			t.Fatalf("dump.Open: %v", err)
		}
		uid := "@alice:hooks.example.org"
		srv.mu.Lock()
		srv.tokens["tok-hook"] = tokenSession{userID: uid, deviceID: "DEV_HOOK"}
		srv.mu.Unlock()
		if err := store.WriteSession(uid, &dump.SessionData{UserID: uid, AccessToken: "tok-hook"}); err != nil {
			t.Fatalf("WriteSession: %v", err)
		}
		if err := store.WriteManifest(&dump.ManifestState{Phase: dump.PhaseFederatedSync}); err != nil {
			t.Fatalf("WriteManifest: %v", err)
		}
		cfg := makeCleanupConfig("hooks.example.org", srv.server.URL, store.Root(), uid)

		removeSession = func(_ *dump.Store, _ string) error {
			return errors.New("remove session boom")
		}
		if err := Run(context.Background(), cfg, store, nil); err == nil || !strings.Contains(err.Error(), "remove session boom") {
			t.Fatalf("expected removeSession error, got %v", err)
		}
		removeSession = origRemove

		writeManifest = func(_ *dump.Store, _ *dump.ManifestState) error {
			return errors.New("manifest write boom")
		}
		if err := Run(context.Background(), cfg, store, nil); err == nil || !strings.Contains(err.Error(), "update manifest phase after cleanup") {
			t.Fatalf("expected manifest write failure, got %v", err)
		}
	})
}
