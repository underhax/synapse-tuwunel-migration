package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/signingkey"
)

func TestRunHappyPathAndIdempotentRerun(t *testing.T) {
	t.Parallel()

	fix := setupFedFixture(t, "happy.example.com")
	ctx := context.Background()
	log := zerolog.Nop()

	if err := Run(ctx, fix.cfg, fix.store, &log); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	verifyFirstPassState(t, fix)

	fix.srv.mu.Lock()
	putsAfterFirst := fix.srv.tagPutCount
	fix.srv.mu.Unlock()
	if putsAfterFirst != 4 {
		t.Fatalf("expected 4 tag PUTs (skipping Bob matching m.lowpriority), got %d", putsAfterFirst)
	}

	if err := Run(ctx, fix.cfg, fix.store, nil); err != nil {
		t.Fatalf("idempotent second Run failed: %v", err)
	}

	fix.srv.mu.Lock()
	defer fix.srv.mu.Unlock()
	aliceJoinKey := fix.aliceID + "|" + fix.fedRoomOne
	if fix.srv.joinCount[aliceJoinKey] != 1 {
		t.Fatalf("expected idempotent rerun to skip duplicate join, count=%d", fix.srv.joinCount[aliceJoinKey])
	}
	if fix.srv.sigUploadCount != 2 {
		t.Fatalf("expected no additional signature uploads on second run, got %d", fix.srv.sigUploadCount)
	}
	if fix.srv.tagPutCount != putsAfterFirst {
		t.Fatalf("expected zero additional tag PUTs on idempotent rerun, got %d -> %d", putsAfterFirst, fix.srv.tagPutCount)
	}
}

func verifyFirstPassState(t *testing.T, fix *fedFixture) {
	t.Helper()

	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if manifest.Phase != dump.PhaseFederatedSync {
		t.Fatalf("manifest phase = %q, want %q", manifest.Phase, dump.PhaseFederatedSync)
	}
	if manifest.LocalRoomMap["!old:"+fix.cfg.ServerName] != "!new:"+fix.cfg.ServerName || !manifest.ProvisionedUsers[fix.aliceID] {
		t.Fatalf("manifest metadata unexpectedly altered: %+v", manifest)
	}
	if manifest.ServerSigningKeyID != fix.srv.serverKeyID || manifest.ServerSigningPublicKey != fix.srv.serverPubB64 {
		t.Fatalf("manifest signing key metadata altered: %+v", manifest)
	}

	bobSess, err := fix.store.ReadSession(fix.bobID)
	if err != nil || bobSess.AccessToken == "" || bobSess.AccessToken == "bob-expired-token" {
		t.Fatalf("expected refreshed Bob session.json after 401 fallback, got sess=%+v err=%v", bobSess, err)
	}

	if !verifySignatureOnMock(t, fix.srv, fix.carolID, fix.aliceID, fix.aliceUserKP.PublicKey()) {
		t.Fatalf("missing valid cross-signing signature on %s", fix.carolID)
	}
	if !verifySignatureOnMock(t, fix.srv, fix.daveID, fix.aliceID, fix.aliceUserKP.PublicKey()) {
		t.Fatalf("missing valid cross-signing signature on %s", fix.daveID)
	}

	verifyFedJoinAndTags(t, fix)
}

func verifyFedJoinAndTags(t *testing.T, fix *fedFixture) {
	t.Helper()
	fix.srv.mu.Lock()
	defer fix.srv.mu.Unlock()
	aliceJoinKey := fix.aliceID + "|" + fix.fedRoomOne
	if via := fix.srv.joinViaCalls[aliceJoinKey]; !slices.Equal(via, fix.fedRoomOneVia) {
		t.Fatalf("unexpected via query params sent on join: %v", via)
	}
	aliceTags := fix.srv.users[fix.aliceID].roomTags[id.RoomID(fix.fedRoomOne)]
	if len(aliceTags) != 2 {
		t.Fatalf("expected 2 tags on Alice federated room, got %d", len(aliceTags))
	}
	var updatedTag event.TagMetadata
	if err := json.Unmarshal(fix.srv.users[fix.bobID].roomTags[id.RoomID(fix.fedRoomOne)]["u.updated"], &updatedTag); err != nil || updatedTag.Order.String() != "0.9" {
		t.Fatalf("expected Bob mismatched tag to be updated to 0.9, got %+v err=%v", updatedTag, err)
	}
}

func TestRunPartialFederatedFailuresLogWarningsAndContinue(t *testing.T) {
	t.Parallel()

	fix := setupFedFixture(t, "partial.example.net")
	ctx := context.Background()

	fix.srv.mu.Lock()
	fix.srv.joinErrors[fix.aliceID+"|"+fix.fedRoomOne] = http.StatusBadGateway
	fix.srv.keyFailures["unreachable.example.net"] = map[string]int{"status": 504}
	fix.srv.keyFailures["alpha.example.org"] = map[string]bool{"timeout": true}
	delete(fix.srv.masterKeys, fix.carolID)
	fix.srv.masterKeys[fix.daveID] = mautrix.CrossSigningKeys{
		UserID: id.UserID(fix.daveID),
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
	}
	fix.srv.mu.Unlock()

	var logBuf strings.Builder
	log := zerolog.New(&logBuf)

	if err := Run(ctx, fix.cfg, fix.store, &log); err != nil {
		t.Fatalf("expected partial remote failures to warn and succeed, got: %v", err)
	}

	fix.srv.mu.Lock()
	aliceRoomOneTags := len(fix.srv.users[fix.aliceID].roomTags[id.RoomID(fix.fedRoomOne)])
	aliceRoomTwoTags := len(fix.srv.users[fix.aliceID].roomTags[id.RoomID(fix.fedRoomTwo)])
	fix.srv.mu.Unlock()

	if aliceRoomOneTags != 0 {
		t.Fatalf("expected no tags applied after failed join on %s, got %d", fix.fedRoomOne, aliceRoomOneTags)
	}
	if aliceRoomTwoTags != 1 {
		t.Fatalf("expected tags applied on joined room %s, got %d", fix.fedRoomTwo, aliceRoomTwoTags)
	}

	logged := logBuf.String()
	for _, want := range []string{"alpha.example.org", "unreachable.example.net", fix.fedRoomOne, fix.carolID} {
		if !strings.Contains(logged, want) {
			t.Fatalf("expected warning log to contain %q, got %s", want, logged)
		}
	}
}

func newInputConfig(serverName, dataDir, pass string) *config.Config {
	return &config.Config{
		ServerName: serverName,
		SynapseURL: "https://synapse." + serverName,
		TuwunelURL: "https://tuwunel." + serverName,
		DataDir:    dataDir,
		Accounts: []config.AccountConfig{
			{
				UserID:          "@user:" + serverName,
				TuwunelPassword: pass,
				RecoveryKey:     "EsTfakeKey",
			},
		},
	}
}

func TestRunInputAndManifestErrors(t *testing.T) {
	t.Parallel()

	validStore, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}

	corruptManifestStore, err := dump.Open(filepath.Join(t.TempDir(), "corrupt_manifest"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	if writeErr := os.WriteFile(filepath.Join(corruptManifestStore.Root(), "manifest_state.json"), []byte("{bad"), 0o600); writeErr != nil {
		t.Fatalf("write corrupt manifest: %v", writeErr)
	}

	corruptFedSrv := newFedMockServer(t, "badfed.example.net")

	corruptFedStore, err := dump.Open(filepath.Join(t.TempDir(), "corrupt_fed"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	if writeErr := corruptFedStore.WriteManifest(&dump.ManifestState{
		Phase:                  dump.PhaseImportedLocal,
		ServerSigningKeyID:     corruptFedSrv.serverKeyID,
		ServerSigningPublicKey: corruptFedSrv.serverPubB64,
	}); writeErr != nil {
		t.Fatalf("WriteManifest: %v", writeErr)
	}
	if writeErr := os.WriteFile(filepath.Join(corruptFedStore.Root(), "rooms", "federated_rooms.json"), []byte("{bad"), 0o600); writeErr != nil {
		t.Fatalf("write corrupt fed rooms: %v", writeErr)
	}
	corruptFedCfg := newInputConfig("badfed.example.net", corruptFedStore.Root(), "pw")
	corruptFedCfg.TuwunelURL = corruptFedSrv.url()

	tests := []struct {
		cfg     *config.Config
		store   *dump.Store
		wantErr error
		name    string
		errText string
	}{
		{name: "nil config", cfg: nil, store: validStore, wantErr: ErrNilConfig},
		{name: "nil store", cfg: newInputConfig("nilstore.example", validStore.Root(), "pw"), store: nil, wantErr: ErrNilStore},
		{
			name:    "invalid config for federate-sync",
			cfg:     newInputConfig("badcfg.example.net", validStore.Root(), ""),
			store:   validStore,
			wantErr: config.ErrMissingTuwunelPass,
		},
		{
			name:    "missing manifest",
			cfg:     newInputConfig("nomani.example.org", validStore.Root(), "pw"),
			store:   validStore,
			wantErr: ErrMissingManifest,
		},
		{
			name:    "corrupt manifest",
			cfg:     newInputConfig("badmani.example", corruptManifestStore.Root(), "pw"),
			store:   corruptManifestStore,
			errText: "read manifest_state.json",
		},
		{
			name:    "corrupt federated rooms",
			cfg:     corruptFedCfg,
			store:   corruptFedStore,
			errText: "read federated_rooms.json",
		},
	}

	ctx := context.Background()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runErr := Run(ctx, tc.cfg, tc.store, nil)
			if runErr == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(runErr, tc.wantErr) {
				t.Fatalf("error = %v, want %v", runErr, tc.wantErr)
			}
			if tc.errText != "" && !strings.Contains(runErr.Error(), tc.errText) {
				t.Fatalf("error = %v, expected substring %q", runErr, tc.errText)
			}
		})
	}
}

type accountErrorCase struct {
	setup   func(t *testing.T, fix *fedFixture)
	wantErr error
	name    string
	errText string
}

func runAccountErrorCases(t *testing.T, cases []accountErrorCase) {
	t.Helper()
	ctx := context.Background()
	for idx, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fix := setupFedFixture(t, "sub"+strconv.Itoa(idx)+".example.net")
			tc.setup(t, fix)
			runErr := Run(ctx, fix.cfg, fix.store, nil)
			if tc.wantErr == nil && tc.errText == "" {
				if runErr != nil {
					t.Fatalf("expected nil error, got %v", runErr)
				}
				return
			}
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
}

func TestRunAccountAndSessionErrorBranches(t *testing.T) {
	t.Parallel()

	cases := []accountErrorCase{
		{
			name: "corrupt session.json fails cleanly",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fix.store.Root(), "accounts", fix.aliceID, "session.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("corrupt session: %v", err)
				}
			},
			errText: "read session.json",
		},
		{
			name: "non-401 whoami error fails",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["GET /_matrix/client/v3/account/whoami"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "validate saved Tuwunel session",
		},
		{
			name: "login failure when session missing",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := fix.store.RemoveSession(fix.aliceID); err != nil {
					t.Fatalf("RemoveSession: %v", err)
				}
				fix.cfg.Accounts[0].TuwunelPassword = "wrong-password"
			},
			errText: "login on Tuwunel",
		},
		{
			name: "empty session access token falls back to password login",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := fix.store.WriteSession(fix.aliceID, &dump.SessionData{UserID: fix.aliceID}); err != nil {
					t.Fatalf("WriteSession empty: %v", err)
				}
			},
		},
		{
			name: "corrupt identity.json",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fix.store.Root(), "accounts", fix.aliceID, "identity.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("corrupt identity: %v", err)
				}
			},
			errText: "read identity.json",
		},
		{
			name: "invalid cross-signing seeds",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := fix.store.WriteIdentity(fix.aliceID, &dump.IdentityData{
					UserID:     fix.aliceID,
					MasterSeed: []byte("short"),
				}); err != nil {
					t.Fatalf("WriteIdentity bad: %v", err)
				}
			},
			wantErr: ErrInvalidLocalSeed,
		},
		{
			name: "corrupt profile.json",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fix.store.Root(), "accounts", fix.aliceID, "profile.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("corrupt profile: %v", err)
				}
			},
			errText: "read profile.json",
		},
		{
			name: "joined_rooms HTTP 500 error",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["GET /_matrix/client/v3/joined_rooms"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "fetch joined rooms",
		},
		{
			name: "joined_rooms null payload handled safely",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.returnedNullJoin = true
				fix.srv.mu.Unlock()
			},
		},
	}

	runAccountErrorCases(t, cases)
}

func TestRunRoomTagsAndTrustGraphErrorBranches(t *testing.T) {
	t.Parallel()

	cases := []accountErrorCase{
		{
			name: "missing configured member in federated room",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := fix.store.WriteFederatedRooms(&dump.FederatedRoomsData{
					Rooms: []dump.FederatedRoom{
						{RoomID: fix.fedRoomOne, JoinedLocalUsers: []string{"@ghost:example.com"}},
					},
				}); err != nil {
					t.Fatalf("WriteFederatedRooms: %v", err)
				}
			},
			wantErr: ErrMissingMember,
		},
		{
			name: "get tags HTTP 500 error",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["GET /_matrix/client/v3/user/"+fix.aliceID+"/rooms/"+fix.fedRoomTwo+"/tags"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "fetch existing room tags",
		},
		{
			name: "add tag HTTP 500 error",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["PUT /_matrix/client/v3/user/"+fix.aliceID+"/rooms/"+fix.fedRoomTwo+"/tags/u.work"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "add tag u.work",
		},
		{
			name: "corrupt trust_graph.json",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fix.store.Root(), "accounts", fix.aliceID, "trust_graph.json"), []byte("{bad"), 0o600); err != nil {
					t.Fatalf("corrupt trust_graph: %v", err)
				}
			},
			errText: "read trust_graph.json",
		},
		{
			name: "query keys HTTP 500 error",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["POST /_matrix/client/v3/keys/query"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "query external master keys",
		},
		{
			name: "external master key mismatch fails fast",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				altKey, _ := generateSigningPair(t)
				fix.srv.mu.Lock()
				fix.srv.masterKeys[fix.carolID] = buildMasterKeyObj(fix.carolID, altKey.PublicKey())
				fix.srv.mu.Unlock()
			},
			wantErr: ErrMasterKeyMismatch,
		},
		{
			name: "signature upload HTTP 500 error",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.forceStatus["POST /_matrix/client/v3/keys/signatures/upload"] = http.StatusInternalServerError
				fix.srv.mu.Unlock()
			},
			errText: "sign external contact",
		},
	}

	runAccountErrorCases(t, cases)
}

func TestRunSigningKeyVerificationErrors(t *testing.T) {
	t.Parallel()

	cases := []accountErrorCase{
		{
			name: "missing manifest signing key metadata",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				manifest, err := fix.store.ReadManifest()
				if err != nil {
					t.Fatalf("ReadManifest: %v", err)
				}
				manifest.ServerSigningKeyID = ""
				if writeErr := fix.store.WriteManifest(manifest); writeErr != nil {
					t.Fatalf("WriteManifest: %v", writeErr)
				}
			},
			wantErr: signingkey.ErrMissingServerKeyState,
		},
		{
			name: "federation disabled 403 rejected",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.federationDisabled = true
				fix.srv.mu.Unlock()
			},
			wantErr: signingkey.ErrServerKeyUnavailable,
		},
		{
			name: "server public key mismatch rejected",
			setup: func(t *testing.T, fix *fedFixture) {
				t.Helper()
				manifest, err := fix.store.ReadManifest()
				if err != nil {
					t.Fatalf("ReadManifest: %v", err)
				}
				manifest.ServerSigningPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				if writeErr := fix.store.WriteManifest(manifest); writeErr != nil {
					t.Fatalf("WriteManifest: %v", writeErr)
				}
			},
			wantErr: signingkey.ErrServerKeyMismatch,
		},
		{
			name: "invalid server key response signature rejected",
			setup: func(_ *testing.T, fix *fedFixture) {
				fix.srv.mu.Lock()
				fix.srv.invalidServerKeySig = true
				fix.srv.mu.Unlock()
			},
			wantErr: signingkey.ErrServerKeySigInvalid,
		},
	}

	runAccountErrorCases(t, cases)
}

func TestRunContextCanceledDuringJoin(t *testing.T) {
	t.Parallel()

	fix := setupFedFixture(t, "canceled.example.org")
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	var logBuf strings.Builder
	log := zerolog.New(&logBuf)
	cli, connErr := mautrix.NewClient(fix.srv.url(), id.UserID(fix.aliceID), "alice-valid-token")
	if connErr != nil {
		t.Fatalf("NewClient: %v", connErr)
	}
	acc := &fedAccount{
		cli:         cli,
		joinedRooms: map[string]struct{}{},
		userID:      fix.aliceID,
	}
	stats := &syncStats{}
	joined, joinErr := ensureUserJoinedRoom(canceledCtx, acc, &dump.FederatedRoom{
		RoomID:     fix.fedRoomOne,
		ViaServers: []string{"canceled.example.org"},
	}, stats, &log)
	if joined || !errors.Is(joinErr, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got joined=%v err=%v", joined, joinErr)
	}

	syncErr := syncSingleFederatedRoom(canceledCtx, &dump.FederatedRoom{
		RoomID:           fix.fedRoomOne,
		JoinedLocalUsers: []string{fix.aliceID},
		ViaServers:       []string{"canceled.example.org"},
	}, map[string]*fedAccount{fix.aliceID: acc}, stats, &log)
	if !errors.Is(syncErr, context.Canceled) {
		t.Fatalf("expected syncSingleFederatedRoom to return context.Canceled, got %v", syncErr)
	}
}

func TestRunDefaultWrappersAndHooks(t *testing.T) {
	t.Run("defaultWriteSession and defaultWriteManifest error wrappers", func(t *testing.T) {
		badStore, err := dump.Open(filepath.Join(t.TempDir(), "blocker_dump"))
		if err != nil {
			t.Fatalf("dump.Open: %v", err)
		}
		if mkErr := os.MkdirAll(filepath.Join(badStore.Root(), "manifest_state.json", "nested"), 0o700); mkErr != nil {
			t.Fatalf("mkdir manifest blocker: %v", mkErr)
		}
		if err := defaultWriteManifest(badStore, &dump.ManifestState{}); err == nil {
			t.Fatal("expected defaultWriteManifest error when target is non-empty directory")
		}
		if mkErr := os.MkdirAll(filepath.Join(badStore.Root(), "accounts", "@blocker:blocker.example", "session.json", "nested"), 0o700); mkErr != nil {
			t.Fatalf("mkdir session blocker: %v", mkErr)
		}
		if err := defaultWriteSession(badStore, "@blocker:blocker.example", &dump.SessionData{UserID: "@blocker:blocker.example"}); err == nil {
			t.Fatal("expected defaultWriteSession error when target is non-empty directory")
		}
	})

	t.Run("injected newOlmMachine writeSession writeManifest hooks", func(t *testing.T) {
		fix := setupFedFixture(t, "hooks.example.com")
		origOlm := newOlmMachine
		origSession := writeSession
		origManifest := writeManifest
		t.Cleanup(func() {
			newOlmMachine = origOlm
			writeSession = origSession
			writeManifest = origManifest
		})

		newOlmMachine = func(_ context.Context, _ *mautrix.Client, _ *zerolog.Logger) (*crypto.OlmMachine, *mautrix.MemoryStateStore, error) {
			return nil, nil, errors.New("olm init boom")
		}
		if err := Run(context.Background(), fix.cfg, fix.store, nil); err == nil || !strings.Contains(err.Error(), "init olm machine") {
			t.Fatalf("expected olm init failure, got %v", err)
		}
		newOlmMachine = origOlm

		writeSession = func(_ *dump.Store, _ string, _ *dump.SessionData) error {
			return errors.New("session write boom")
		}
		if err := Run(context.Background(), fix.cfg, fix.store, nil); err == nil || !strings.Contains(err.Error(), "session write boom") {
			t.Fatalf("expected session write failure, got %v", err)
		}
		writeSession = origSession

		writeManifest = func(_ *dump.Store, _ *dump.ManifestState) error {
			return errors.New("manifest write boom")
		}
		if err := Run(context.Background(), fix.cfg, fix.store, nil); err == nil || !strings.Contains(err.Error(), "write final manifest state") {
			t.Fatalf("expected manifest write failure, got %v", err)
		}
	})
}

func TestTagAlreadyMatchesEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desiredOrder  *float64
		name          string
		existingKey   string
		existingOrder string
		nilMap        bool
		hasTarget     bool
		want          bool
	}{
		{name: "empty map", nilMap: true, want: false},
		{name: "missing tag", existingKey: "u.other", want: false},
		{name: "nil desired vs empty order", hasTarget: true, existingOrder: "", desiredOrder: nil, want: true},
		{name: "nil desired vs present order", hasTarget: true, existingOrder: "0.2", desiredOrder: nil, want: false},
		{name: "desired order vs empty existing", hasTarget: true, existingOrder: "", desiredOrder: new(0.5), want: false},
		{name: "desired order vs invalid existing", hasTarget: true, existingOrder: "abc", desiredOrder: new(0.5), want: false},
		{name: "desired order vs matching existing", hasTarget: true, existingOrder: "0.5", desiredOrder: new(0.5), want: true},
		{name: "desired order vs different existing", hasTarget: true, existingOrder: "0.5", desiredOrder: new(0.75), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var existing event.Tags
			if !tc.nilMap {
				key := tc.existingKey
				if tc.hasTarget {
					key = "u.tag"
				}
				existing = event.Tags{
					event.RoomTag(key): {Order: json.Number(tc.existingOrder)},
				}
			}
			got := tagAlreadyMatches(existing, "u.tag", tc.desiredOrder)
			if got != tc.want {
				t.Fatalf("tagAlreadyMatches = %v, want %v", got, tc.want)
			}
		})
	}
}
