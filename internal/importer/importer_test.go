package importer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
	"github.com/underhax/synapse-tuwunel-migration/internal/signingkey"
)

type backupAuthDataVerify struct {
	Signatures signatures.Signatures `json:"signatures"`
	PublicKey  id.Ed25519            `json:"public_key"`
}

func TestRunFullHappyPathAndIdempotentRerun(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "example.com")
	ctx := context.Background()
	log := zerolog.Nop()

	if err := Run(ctx, fix.cfg, fix.store, &log); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	verifyManifestAndAccounts(t, fix)
	verifyRoomsAndSpaces(t, fix)
	verifyReplayedNotesEndToEnd(t, fix)

	if err := Run(ctx, fix.cfg, fix.store, nil); err != nil {
		t.Fatalf("idempotent second Run failed: %v", err)
	}

	fix.tuwunel.mu.Lock()
	defer fix.tuwunel.mu.Unlock()
	if len(fix.tuwunel.registered) != 2 {
		t.Fatalf("expected no duplicate registrations on rerun, got %d", len(fix.tuwunel.registered))
	}
	if len(fix.tuwunel.loggedOut) != 3 {
		t.Fatalf("expected 3 previous sessions logged out on rerun, got %d", len(fix.tuwunel.loggedOut))
	}
	if len(fix.tuwunel.rooms) != 5 {
		t.Fatalf("expected 5 rooms total without duplicates after rerun, got %d", len(fix.tuwunel.rooms))
	}
}

func verifyManifestAndAccounts(t *testing.T, fix *importFixture) {
	t.Helper()
	dmNewID := verifyManifestState(t, fix)
	verifyRestoredUsers(t, fix, dmNewID)
}

func verifyManifestState(t *testing.T, fix *importFixture) id.RoomID {
	t.Helper()
	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if manifest.Phase != dump.PhaseImportedLocal {
		t.Fatalf("unexpected manifest phase: %s", manifest.Phase)
	}
	if manifest.ServerSigningKeyID != fix.tuwunel.serverKeyID || manifest.ServerSigningPublicKey != fix.tuwunel.serverPubB64 {
		t.Fatalf("manifest signing key metadata altered: %+v", manifest)
	}
	if !manifest.ProvisionedUsers[fix.aliceID] || !manifest.ProvisionedUsers[fix.bobID] {
		t.Fatalf("missing ProvisionedUsers entries: %+v", manifest.ProvisionedUsers)
	}
	sess, err := fix.store.ReadSession(fix.aliceID)
	if err != nil || sess.AccessToken == "" || sess.DeviceID == "" {
		t.Fatalf("expected valid session.json for Alice, got sess=%+v err=%v", sess, err)
	}
	return id.RoomID(manifest.LocalRoomMap[fix.dmID])
}

func verifyRestoredUsers(t *testing.T, fix *importFixture, dmNewID id.RoomID) {
	t.Helper()
	fix.tuwunel.mu.Lock()
	defer fix.tuwunel.mu.Unlock()
	if len(fix.tuwunel.registered) != 2 || fix.tuwunel.registered[0].Username != "alice" || !fix.tuwunel.registered[0].Admin || fix.tuwunel.registered[1].Username != "bob" || fix.tuwunel.registered[1].Admin {
		t.Fatalf("unexpected registration order/admin flags: %+v", fix.tuwunel.registered)
	}

	aliceUser := fix.tuwunel.users[fix.aliceID]
	bobUser := fix.tuwunel.users[fix.bobID]
	if aliceUser.DisplayName != "Alice Display" || aliceUser.AvatarURL == "" {
		t.Fatalf("alice profile not restored: %+v", aliceUser)
	}
	if len(aliceUser.AccountData) < 7 {
		t.Fatalf("expected SSSS + m.ignored_user_list + m.direct account data, got %d entries", len(aliceUser.AccountData))
	}

	var mDirect map[string][]string
	if unmErr := json.Unmarshal(aliceUser.AccountData["m.direct"], &mDirect); unmErr != nil {
		t.Fatalf("unmarshal m.direct: %v", unmErr)
	}
	if len(mDirect[fix.bobID]) != 1 || mDirect[fix.bobID][0] != dmNewID.String() {
		t.Fatalf("m.direct not remapped: %+v", mDirect)
	}
	if _, hasTag := aliceUser.RoomTags[dmNewID]["m.favourite"]; !hasTag {
		t.Fatalf("missing favourite tag on recreated DM room %s", dmNewID)
	}
	if len(aliceUser.RoomTags[id.RoomID(fix.fedRoomID)]) != 0 {
		t.Fatalf("federated room tag should not be applied during import-local")
	}
	verifyAliceCryptographicSignatures(t, fix, aliceUser, bobUser)
}

func verifyAliceCryptographicSignatures(t *testing.T, fix *importFixture, aliceUser, bobUser *mockTuwunelUser) {
	t.Helper()
	var authData backupAuthDataVerify
	if unmErr := json.Unmarshal(aliceUser.BackupAuthData, &authData); unmErr != nil {
		t.Fatalf("unmarshal backup auth_data: %v", unmErr)
	}
	verifiedAuth, sigErr := signatures.VerifySignatureJSON(&authData, id.UserID(fix.aliceID), fix.aliceCrypto.masterPK.PublicKey().String(), fix.aliceCrypto.masterPK.PublicKey())
	if sigErr != nil || !verifiedAuth {
		t.Fatalf("backup auth_data master signature invalid: verified=%v err=%v", verifiedAuth, sigErr)
	}

	verifiedTrust, trustErr := signatures.VerifySignatureJSON(
		bobUser.MasterKey,
		id.UserID(fix.aliceID),
		fix.aliceCrypto.userPK.PublicKey().String(),
		fix.aliceCrypto.userPK.PublicKey(),
	)
	if trustErr != nil || !verifiedTrust {
		t.Fatalf("expected Alice UserSigning signature on Bob MasterKey: verified=%v err=%v", verifiedTrust, trustErr)
	}
}

func verifyRoomsAndSpaces(t *testing.T, fix *importFixture) {
	t.Helper()
	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	dmNewID := id.RoomID(manifest.LocalRoomMap[fix.dmID])
	spaceNewID := id.RoomID(manifest.LocalRoomMap[fix.spaceID])

	fix.tuwunel.mu.Lock()
	defer fix.tuwunel.mu.Unlock()
	spaceRoom := fix.tuwunel.rooms[spaceNewID]
	dmChild := spaceRoom.SpaceChildren[dmNewID.String()]
	if len(dmChild.Via) != 1 || dmChild.Via[0] != fix.serverName || !dmChild.Suggested || dmChild.Order != fix.noteOrder {
		t.Fatalf("unexpected space child metadata for remapped DM: %+v", dmChild)
	}
	if fedChild := spaceRoom.SpaceChildren[fix.fedRoomID]; len(fedChild.Via) != 1 || fedChild.Via[0] != "example.org" {
		t.Fatalf("unexpected federated space child metadata: %+v", fedChild)
	}

	plainNotesID := id.RoomID(manifest.LocalRoomMap[fix.notesPlainID])
	if len(fix.tuwunel.rooms[plainNotesID].Timeline) != 2 {
		t.Fatalf("expected 1 plaintext note + 1 reaction in Bob notes room")
	}

	carolNotesID := id.RoomID(manifest.LocalRoomMap[fix.notesCarolID])
	if len(fix.tuwunel.rooms[carolNotesID].Timeline) != 0 {
		t.Fatalf("expected empty encrypted notes room without backup for Carol")
	}
}

func verifyReplayedNotesEndToEnd(t *testing.T, fix *importFixture) {
	t.Helper()
	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	encNotesID := id.RoomID(manifest.LocalRoomMap[fix.notesEncID])
	msgs, reacts := decryptReplayedNotes(t, fix.aliceCrypto, fix.tuwunel, encNotesID)
	if len(msgs) != 2 || len(reacts) != 1 {
		t.Fatalf("expected 2 decrypted notes and 1 reaction, got msgs=%d reacts=%d", len(msgs), len(reacts))
	}
	if msgs[0].Body != fix.noteEditBody || msgs[0].FormattedBody == "" {
		t.Fatalf("unexpected first decrypted note: %+v", msgs[0])
	}
	if msgs[1].RelatesTo == nil || msgs[1].RelatesTo.GetReplyTo() == "" || msgs[1].RelatesTo.GetReplyTo() == id.EventID(fix.firstNoteID) {
		t.Fatalf("reply target not remapped cleanly: %+v", msgs[1].RelatesTo)
	}
	if reacts[0].RelatesTo.GetAnnotationID() != msgs[1].RelatesTo.GetReplyTo() || reacts[0].RelatesTo.GetAnnotationKey() != "👍" {
		t.Fatalf("reaction target mismatch: %+v", reacts[0].RelatesTo)
	}
	if msgs[1].File == nil {
		t.Fatalf("expected encrypted attachment FileInfo on second note")
	}
	verifyAttachmentContent(t, fix.tuwunel, msgs[1].File, []byte("secret-note-image-payload"))
}

func TestRunIncrementalSpaceChildAndBackupMismatch(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "alpha.example")
	ctx := context.Background()
	log := zerolog.Nop()

	if err := Run(ctx, fix.cfg, fix.store, &log); err != nil {
		t.Fatalf("initial Run failed: %v", err)
	}

	fix.tuwunel.mu.Lock()
	fix.tuwunel.users[fix.aliceID].BackupAuthData = json.RawMessage(`{"public_key":"MISMATCHED"}`)
	fix.tuwunel.mu.Unlock()

	if sessErr := fix.store.WriteSession(fix.carolID, &dump.SessionData{
		UserID:        fix.carolID,
		HomeserverURL: fix.tuwunel.srv.URL,
		AccessToken:   "expired-invalid-token",
		DeviceID:      "OLD",
	}); sessErr != nil {
		t.Fatalf("WriteSession expired: %v", sessErr)
	}

	localRooms, err := fix.store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	extraOldID := "!extra-room:" + fix.serverName
	localRooms.Rooms = append(localRooms.Rooms,
		dump.LocalRoom{
			OldRoomID:       extraOldID,
			Category:        dump.RoomCategoryLocal,
			OriginalCreator: fix.aliceID,
			ChosenCreator:   fix.aliceID,
			Name:            "Delta Child Room",
			JoinedMembers:   []string{fix.aliceID},
		},
		dump.LocalRoom{
			OldRoomID:       "!empty-space:" + fix.serverName,
			Category:        dump.RoomCategoryLocal,
			RoomType:        "m.space",
			OriginalCreator: fix.aliceID,
			ChosenCreator:   fix.aliceID,
			JoinedMembers:   []string{fix.aliceID},
		},
	)
	localRooms.Rooms[0].SpaceChildren = append(localRooms.Rooms[0].SpaceChildren, dump.SpaceChildEntry{
		ChildRoomID: extraOldID,
	})
	if writeErr := fix.store.WriteLocalRooms(localRooms); writeErr != nil {
		t.Fatalf("WriteLocalRooms delta: %v", writeErr)
	}

	if runErr := Run(ctx, fix.cfg, fix.store, &log); runErr != nil {
		t.Fatalf("delta Run failed: %v", runErr)
	}

	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	extraNewID := manifest.LocalRoomMap[extraOldID]
	if extraNewID == "" {
		t.Fatalf("expected delta child room mapped in manifest")
	}
	topSpaceNewID := id.RoomID(manifest.LocalRoomMap[fix.spaceID])
	fix.tuwunel.mu.Lock()
	defer fix.tuwunel.mu.Unlock()
	if _, ok := fix.tuwunel.rooms[topSpaceNewID].SpaceChildren[extraNewID]; !ok {
		t.Fatalf("expected existing parent space to sync newly created delta child %s", extraNewID)
	}
	if fix.tuwunel.users[fix.aliceID].BackupVersion == "" {
		t.Fatalf("expected recreated backup version after mismatched server public key")
	}
}

func TestBatchedBackupUploadAndEmptyRoom(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "beta.example")
	ctx := context.Background()
	log := zerolog.Nop()

	roomsMap := make(map[string]dump.RoomKeyBackupRoom, 2)
	roomsMap["!empty:"+fix.serverName] = dump.RoomKeyBackupRoom{Sessions: map[string]dump.RoomKeySession{}}
	largeSessions := make(map[string]dump.RoomKeySession, backupUploadBatchSize+15)
	for i := range backupUploadBatchSize + 15 {
		largeSessions["sess-"+strconv.Itoa(i)] = dump.RoomKeySession{
			SessionData: json.RawMessage(`{"ciphertext":"abc","ephemeral":"def","mac":"123"}`),
		}
	}
	batchRoomID := "!batch:" + fix.serverName
	roomsMap[batchRoomID] = dump.RoomKeyBackupRoom{Sessions: largeSessions}
	if err := fix.store.WriteRoomKeys(fix.aliceID, &dump.RoomKeysData{
		UserID: fix.aliceID,
		Rooms:  roomsMap,
	}); err != nil {
		t.Fatalf("WriteRoomKeys batched: %v", err)
	}

	if err := Run(ctx, fix.cfg, fix.store, &log); err != nil {
		t.Fatalf("Run with batched room_keys failed: %v", err)
	}

	fix.tuwunel.mu.Lock()
	uploadedCount := len(fix.tuwunel.users[fix.aliceID].BackupSessions[id.RoomID(batchRoomID)])
	fix.tuwunel.mu.Unlock()
	if uploadedCount != backupUploadBatchSize+15 {
		t.Fatalf("expected %d batched sessions uploaded, got %d", backupUploadBatchSize+15, uploadedCount)
	}

	sess, err := fix.store.ReadSession(fix.aliceID)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	cli, _, err := matrix.ConnectWithToken(ctx, fix.tuwunel.srv.URL, fix.aliceID, sess.AccessToken, &log)
	if err != nil {
		t.Fatalf("ConnectWithToken: %v", err)
	}
	fix.tuwunel.failRoute(http.MethodPut, "/room_keys/keys", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "batch fail")
	if err := uploadBackupSessionsBatched(ctx, cli, "1", map[string]dump.RoomKeyBackupRoom{
		"!onlyempty:" + fix.serverName: {},
	}); err != nil {
		t.Fatalf("expected zero-session flush to succeed without HTTP call: %v", err)
	}
	if err := uploadBackupSessionsBatched(ctx, cli, "1", roomsMap); err == nil {
		t.Fatalf("expected mid-loop batched flush failure")
	}
}

func TestRoomVersion11AndEmptyDefaults(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "gamma.example")
	fix.cfg.LocalRoomVersion = "11"
	fix.cfg.ReplaySingleUserNotes = false

	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	manifest.LocalRoomMap = nil
	manifest.ProvisionedUsers = nil
	if writeErr := fix.store.WriteManifest(manifest); writeErr != nil {
		t.Fatalf("WriteManifest: %v", writeErr)
	}

	if writeErr := fix.store.WriteLocalRooms(&dump.LocalRoomsData{
		Rooms: []dump.LocalRoom{
			{
				OldRoomID:       "!v11room:" + fix.serverName,
				Category:        dump.RoomCategoryLocal,
				OriginalCreator: fix.aliceID,
				ChosenCreator:   fix.aliceID,
				JoinedMembers:   []string{fix.aliceID},
			},
		},
	}); writeErr != nil {
		t.Fatalf("WriteLocalRooms v11: %v", writeErr)
	}

	log := zerolog.Nop()
	if runErr := Run(context.Background(), fix.cfg, fix.store, &log); runErr != nil {
		t.Fatalf("Run v11 failed: %v", runErr)
	}
	if cc := buildCreationContent(&dump.LocalRoom{}, "11"); cc != nil {
		t.Fatalf("expected nil creation content for plain v11 room, got %+v", cc)
	}
	req, reqErr := buildCreateRoomRequest(context.Background(), &config.Config{}, fix.store, nil, &dump.LocalRoom{
		ChosenCreator: fix.aliceID,
		JoinedMembers: []string{fix.aliceID},
	})
	if reqErr != nil || req.RoomVersion != roomVersionTwelve {
		t.Fatalf("expected fallback room version 12, got req=%+v err=%v", req, reqErr)
	}
}

func TestRunPreconditionAndValidationErrors(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "delta.example")
	ctx := context.Background()

	if err := Run(ctx, nil, fix.store, nil); !errors.Is(err, ErrNilConfig) {
		t.Fatalf("expected ErrNilConfig, got %v", err)
	}
	if err := Run(ctx, fix.cfg, nil, nil); !errors.Is(err, ErrNilStore) {
		t.Fatalf("expected ErrNilStore, got %v", err)
	}
	badCfg := *fix.cfg
	badCfg.ServerName = ""
	if err := Run(ctx, &badCfg, fix.store, nil); err == nil {
		t.Fatalf("expected ValidateForMode error")
	}

	missingStore, err := dump.Open(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	if runErr := Run(ctx, fix.cfg, missingStore, nil); !errors.Is(runErr, ErrMissingManifest) {
		t.Fatalf("expected ErrMissingManifest, got %v", runErr)
	}

	if writeErr := os.WriteFile(filepath.Join(missingStore.Root(), "manifest_state.json"), []byte("{bad"), 0o600); writeErr != nil {
		t.Fatalf("write corrupt manifest: %v", writeErr)
	}
	if runErr := Run(ctx, fix.cfg, missingStore, nil); runErr == nil {
		t.Fatalf("expected manifest decode error")
	}

	noSecretCfg := *fix.cfg
	noSecretCfg.TuwunelSharedSecret = ""
	if runErr := Run(ctx, &noSecretCfg, fix.store, nil); !errors.Is(runErr, matrix.ErrEmptySharedSecret) {
		t.Fatalf("expected ErrEmptySharedSecret, got %v", runErr)
	}

	noRoomsStore, err := dump.Open(filepath.Join(t.TempDir(), "norooms"))
	if err != nil {
		t.Fatalf("dump.Open noRooms: %v", err)
	}
	if writeErr := noRoomsStore.WriteSigningKeyTOML([]byte("[global.admin.room]\n")); writeErr != nil {
		t.Fatalf("WriteSigningKeyTOML noRooms: %v", writeErr)
	}
	if writeErr := noRoomsStore.WriteManifest(&dump.ManifestState{
		ProvisionedUsers: map[string]bool{
			fix.aliceID: true,
			fix.bobID:   true,
			fix.carolID: true,
		},
		ServerSigningKeyID:     fix.tuwunel.serverKeyID,
		ServerSigningPublicKey: fix.tuwunel.serverPubB64,
	}); writeErr != nil {
		t.Fatalf("WriteManifest noRooms: %v", writeErr)
	}
	if runErr := Run(ctx, &noSecretCfg, noRoomsStore, nil); runErr == nil {
		t.Fatalf("expected missing local_rooms.json error")
	}
}

func TestVerifyStagingSigningKey(t *testing.T) {
	t.Parallel()

	t.Run("live 200 OK matching key succeeds", func(t *testing.T) {
		t.Parallel()
		fix := setupImportFixture(t, "livekey.example")
		fix.tuwunel.mu.Lock()
		fix.tuwunel.federationEnabled = true
		fix.tuwunel.mu.Unlock()
		if err := Run(context.Background(), fix.cfg, fix.store, nil); err != nil {
			t.Fatalf("Run with live verified server key failed: %v", err)
		}
	})

	cases := []struct {
		setupCase func(t *testing.T, fix *importFixture)
		wantErr   error
		name      string
	}{
		{
			name: "missing tuwunel import key TOML",
			setupCase: func(t *testing.T, fix *importFixture) {
				t.Helper()
				if err := os.Remove(fix.store.SigningKeyTOMLPath()); err != nil {
					t.Fatalf("Remove key toml: %v", err)
				}
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "insecure tuwunel import key TOML permissions",
			setupCase: func(t *testing.T, fix *importFixture) {
				t.Helper()
				if err := os.Chmod(fix.store.SigningKeyTOMLPath(), 0o200); err != nil {
					t.Fatalf("Chmod key toml: %v", err)
				}
			},
		},
		{
			name: "missing manifest signing key metadata",
			setupCase: func(t *testing.T, fix *importFixture) {
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
			name: "server key endpoint error",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodGet, "/_matrix/key/v2/server", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "key probe error")
			},
			wantErr: signingkey.ErrServerKeyUnavailable,
		},
		{
			name: "mismatched live server public key",
			setupCase: func(t *testing.T, fix *importFixture) {
				t.Helper()
				fix.tuwunel.mu.Lock()
				fix.tuwunel.federationEnabled = true
				fix.tuwunel.mu.Unlock()
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fix := setupImportFixture(t, "keyerr.example")
			tc.setupCase(t, fix)
			log := zerolog.Nop()
			err := Run(context.Background(), fix.cfg, fix.store, &log)
			if err == nil {
				t.Fatalf("expected error in case %q", tc.name)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestImporterRouteErrorBranches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		setupCase func(t *testing.T, fix *importFixture)
		name      string
	}{
		{
			name: "shared secret register failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/_synapse/admin/v1/register", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "reg fail")
			},
		},
		{
			name: "whoami after register failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodGet, "/account/whoami", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "whoami fail")
			},
		},
		{
			name: "password login failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/_matrix/client/v3/login", http.StatusForbidden, mautrix.MForbidden.ErrCode, "login denied")
			},
		},
		{
			name: "non-401 logout failure logs warning and continues",
			setupCase: func(t *testing.T, fix *importFixture) {
				if err := fix.store.WriteSession(fix.aliceID, &dump.SessionData{
					UserID:        fix.aliceID,
					HomeserverURL: fix.tuwunel.srv.URL,
				}); err != nil {
					t.Fatalf("WriteSession empty token: %v", err)
				}
				fix.tuwunel.mu.Lock()
				fix.tuwunel.users[fix.carolID].Tokens["carol-active-tok"] = "CDEV"
				fix.tuwunel.mu.Unlock()
				if err := fix.store.WriteSession(fix.carolID, &dump.SessionData{
					UserID:        fix.carolID,
					HomeserverURL: fix.tuwunel.srv.URL,
					AccessToken:   "carol-active-tok",
					DeviceID:      "CDEV",
				}); err != nil {
					t.Fatalf("WriteSession valid: %v", err)
				}
				fix.tuwunel.failRoute(http.MethodPost, "/_matrix/client/v3/logout", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "logout 500")
				fix.tuwunel.failRoute(http.MethodPost, "/_matrix/client/v3/createRoom", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "stop after auth")
			},
		},
		{
			name: "share keys upload failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/keys/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "keys upload fail")
			},
		},
		{
			name: "publish cross signing keys failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/keys/device_signing/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "uia fail")
			},
		},
		{
			name: "sign own master key signature upload failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/keys/signatures/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "sig fail")
			},
		},
		{
			name: "sign own device query failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/keys/query", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "query fail")
			},
		},
		{
			name: "ssss account data upload failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/account_data/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "account data fail")
			},
		},
		{
			name: "set displayname failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/displayname", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "displayname fail")
			},
		},
		{
			name: "upload avatar media failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/_matrix/media/v3/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "media upload fail")
			},
		},
		{
			name: "set avatar url failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/avatar_url", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "avatar url fail")
			},
		},
		{
			name: "ignored user list upload failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/account_data/m.ignored_user_list", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "ignored list fail")
			},
		},
		{
			name: "key backup latest version non-404 error",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodGet, "/room_keys/version", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "backup check fail")
			},
		},
		{
			name: "create key backup version failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/room_keys/version", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "create backup fail")
			},
		},
		{
			name: "put room keys backup batch failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/room_keys/keys", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "put keys fail")
			},
		},
		{
			name: "create room failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/createRoom", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "create room fail")
			},
		},
		{
			name: "space child state failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/state/m.space.child/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "space child fail")
			},
		},
		{
			name: "room tag put failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/tags/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "tag fail")
			},
		},
		{
			name: "m.direct put failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/account_data/m.direct", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "m.direct fail")
			},
		},
		{
			name: "room auto-join failure",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPost, "/join", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "auto-join fail")
			},
		},
		{
			name: "note message replay failure inside Run",
			setupCase: func(_ *testing.T, fix *importFixture) {
				fix.tuwunel.failRoute(http.MethodPut, "/send/m.room.message/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "replay fail")
			},
		},
		{
			name: "empty room avatar contentType fallback then upload error",
			setupCase: func(t *testing.T, fix *importFixture) {
				profile, err := fix.store.ReadProfile(fix.aliceID)
				if err != nil {
					t.Fatalf("ReadProfile: %v", err)
				}
				profile.Avatar.ContentType = ""
				if writeErr := fix.store.WriteProfile(fix.aliceID, profile); writeErr != nil {
					t.Fatalf("WriteProfile: %v", writeErr)
				}
				fix.tuwunel.failRoute(http.MethodPost, "/media/v3/upload", http.StatusBadRequest, mautrix.MBadJSON.ErrCode, "stop")
			},
		},
		{
			name: "empty raw ssss entry skipped then bad seed fails",
			setupCase: func(t *testing.T, fix *importFixture) {
				fix.aliceCrypto.identityData.RawSSSSAccountData["empty.test"] = nil
				fix.aliceCrypto.identityData.MasterSeed = []byte("short")
				if writeErr := fix.store.WriteIdentity(fix.aliceID, fix.aliceCrypto.identityData); writeErr != nil {
					t.Fatalf("WriteIdentity: %v", writeErr)
				}
			},
		},
		{
			name: "empty raw ssss entry skipped then stops after ssss",
			setupCase: func(t *testing.T, fix *importFixture) {
				fix.aliceCrypto.identityData.RawSSSSAccountData["empty.test"] = nil
				if writeErr := fix.store.WriteIdentity(fix.aliceID, fix.aliceCrypto.identityData); writeErr != nil {
					t.Fatalf("WriteIdentity: %v", writeErr)
				}
				fix.tuwunel.failRoute(http.MethodPost, "/createRoom", http.StatusBadRequest, mautrix.MBadJSON.ErrCode, "stop after ssss")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fix := setupImportFixture(t, "epsilon.example")
			tc.setupCase(t, fix)
			log := zerolog.Nop()
			if err := Run(context.Background(), fix.cfg, fix.store, &log); err == nil {
				t.Fatalf("expected error in case %q", tc.name)
			}
		})
	}
}

func TestImporterStoreErrorBranches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		setupCase func(t *testing.T, fix *importFixture)
		name      string
	}{
		{name: "corrupt prior session json", setupCase: setupCorruptSessionJSON},
		{name: "missing identity file", setupCase: setupRemoveAccountFile("identity.json")},
		{name: "missing profile file", setupCase: setupRemoveAccountFile("profile.json")},
		{name: "missing avatar media blob", setupCase: setupRemoveAvatarMedia},
		{name: "missing room keys file", setupCase: setupRemoveAccountFile("room_keys.json")},
		{name: "invalid megolm backup key bytes", setupCase: setupInvalidBackupKeyBytes},
		{name: "missing chosen creator in accounts", setupCase: setupMissingChosenCreator},
		{name: "missing room member in accounts", setupCase: setupMissingRoomMember},
		{name: "missing room avatar media", setupCase: setupMissingRoomAvatarMedia},
		{name: "room avatar upload failure", setupCase: setupRoomAvatarUploadFailure},
		{name: "missing trust graph file", setupCase: setupRemoveAccountFile("trust_graph.json")},
		{name: "trust graph master key mismatch", setupCase: setupTrustGraphMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fix := setupImportFixture(t, "zeta.example")
			tc.setupCase(t, fix)
			log := zerolog.Nop()
			if err := Run(context.Background(), fix.cfg, fix.store, &log); err == nil {
				t.Fatalf("expected error in case %q", tc.name)
			}
		})
	}
}

func setupRemoveAccountFile(filename string) func(t *testing.T, fix *importFixture) {
	return func(t *testing.T, fix *importFixture) {
		t.Helper()
		if err := os.Remove(filepath.Join(fix.store.Root(), "accounts", fix.aliceID, filename)); err != nil {
			t.Fatalf("Remove %s: %v", filename, err)
		}
	}
}

func setupCorruptSessionJSON(t *testing.T, fix *importFixture) {
	t.Helper()
	p := filepath.Join(fix.store.Root(), "accounts", fix.aliceID)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p, "session.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func setupRemoveAvatarMedia(t *testing.T, fix *importFixture) {
	t.Helper()
	profile, err := fix.store.ReadProfile(fix.aliceID)
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	if remErr := os.Remove(filepath.Join(fix.store.Root(), "media", profile.Avatar.SHA256)); remErr != nil {
		t.Fatalf("Remove media: %v", remErr)
	}
}

func setupInvalidBackupKeyBytes(t *testing.T, fix *importFixture) {
	t.Helper()
	fix.aliceCrypto.identityData.MegolmBackupKey = []byte("invalid")
	if err := fix.store.WriteIdentity(fix.aliceID, fix.aliceCrypto.identityData); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
}

func setupMissingChosenCreator(t *testing.T, fix *importFixture) {
	t.Helper()
	rooms, err := fix.store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	rooms.Rooms[1].ChosenCreator = "@unknown:" + fix.serverName
	if writeErr := fix.store.WriteLocalRooms(rooms); writeErr != nil {
		t.Fatalf("WriteLocalRooms: %v", writeErr)
	}
}

func setupMissingRoomMember(t *testing.T, fix *importFixture) {
	t.Helper()
	rooms, err := fix.store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	rooms.Rooms[1].JoinedMembers = append(rooms.Rooms[1].JoinedMembers, "@stranger:"+fix.serverName)
	if writeErr := fix.store.WriteLocalRooms(rooms); writeErr != nil {
		t.Fatalf("WriteLocalRooms: %v", writeErr)
	}
}

func setupMissingRoomAvatarMedia(t *testing.T, fix *importFixture) {
	t.Helper()
	rooms, err := fix.store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	if remErr := os.Remove(filepath.Join(fix.store.Root(), "media", rooms.Rooms[1].Avatar.SHA256)); remErr != nil {
		t.Fatalf("Remove room avatar: %v", remErr)
	}
}

func setupRoomAvatarUploadFailure(t *testing.T, fix *importFixture) {
	t.Helper()
	profile, err := fix.store.ReadProfile(fix.aliceID)
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	profile.Avatar = nil
	if writeErr := fix.store.WriteProfile(fix.aliceID, profile); writeErr != nil {
		t.Fatalf("WriteProfile: %v", writeErr)
	}
	fix.tuwunel.failRoute(http.MethodPost, "/media/v3/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "room avatar fail")
}

func setupTrustGraphMismatch(t *testing.T, fix *importFixture) {
	t.Helper()
	if err := fix.store.WriteTrustGraph(fix.aliceID, &dump.TrustGraphData{
		UserID: fix.aliceID,
		Contacts: []dump.TrustedContact{
			{UserID: fix.aliceID, MasterKey: "SELF", Local: true},
			{UserID: fix.bobID, MasterKey: "WRONGKEY", Local: true},
		},
	}); err != nil {
		t.Fatalf("WriteTrustGraph: %v", err)
	}
}

func TestImporterPackageHookFailures(t *testing.T) {
	fix := setupImportFixture(t, "hooks.example")
	log := zerolog.Nop()

	t.Run("newOlmMachine error", func(t *testing.T) {
		orig := newOlmMachine
		defer func() { newOlmMachine = orig }()
		newOlmMachine = failingNewOlmMachine
		if err := Run(context.Background(), fix.cfg, fix.store, &log); err == nil {
			t.Fatalf("expected newOlmMachine failure")
		}
	})

	t.Run("joinRoomByID error", func(t *testing.T) {
		orig := joinRoomByID
		defer func() { joinRoomByID = orig }()
		joinRoomByID = failingJoinRoomByID
		localFix := setupImportFixture(t, "joinfail.example")
		if err := Run(context.Background(), localFix.cfg, localFix.store, &log); err == nil {
			t.Fatalf("expected joinRoomByID failure")
		}
	})

	t.Run("write manifest overwrite directory failure", func(t *testing.T) {
		localFix := setupImportFixture(t, "dirfail.example")
		manifestPath := filepath.Join(localFix.store.Root(), "manifest_state.json")
		if remErr := os.Remove(manifestPath); remErr != nil {
			t.Fatalf("Remove manifest: %v", remErr)
		}
		if mkErr := os.MkdirAll(filepath.Join(manifestPath, "nested"), 0o700); mkErr != nil {
			t.Fatalf("MkdirAll manifest blocker: %v", mkErr)
		}
		manifest := &dump.ManifestState{
			LocalRoomMap:     make(map[string]string),
			ProvisionedUsers: make(map[string]bool),
		}
		if _, regErr := authenticateTuwunelAccount(context.Background(), localFix.cfg, localFix.store, manifest, &localFix.cfg.Accounts[0], &log); regErr == nil {
			t.Fatalf("expected WriteManifest failure when target is non-empty directory")
		}
	})

	t.Run("saveSession failure when session target is non-empty directory", func(t *testing.T) {
		localFix := setupImportFixture(t, "sessfail.example")
		sessPath := filepath.Join(localFix.store.Root(), "accounts", localFix.carolID, "session.json")
		if mkErr := os.MkdirAll(filepath.Join(sessPath, "nested"), 0o700); mkErr != nil {
			t.Fatalf("MkdirAll session blocker: %v", mkErr)
		}
		manifest, err := localFix.store.ReadManifest()
		if err != nil {
			t.Fatalf("ReadManifest: %v", err)
		}
		if _, authErr := authenticateTuwunelAccount(context.Background(), localFix.cfg, localFix.store, manifest, &localFix.cfg.Accounts[2], &log); authErr == nil {
			t.Fatalf("expected RemoveSession/WriteSession failure")
		}
	})

	t.Run("syncCreatedSpaceChildren defensive checks", func(t *testing.T) {
		spaceRoomID := "!sp:hooks.example"
		rooms := []dump.LocalRoom{
			{
				OldRoomID:     spaceRoomID,
				RoomType:      spaceRoomType,
				ChosenCreator: fix.aliceID,
				SpaceChildren: []dump.SpaceChildEntry{{ChildRoomID: "!c:hooks.example"}},
			},
		}
		if err := syncCreatedSpaceChildren(context.Background(), fix.serverName, rooms, map[string]string{}, map[string]bool{spaceRoomID: true}, map[string]*importedAccount{}); err != nil {
			t.Fatalf("expected empty mapped spaceID to skip cleanly, got %v", err)
		}
		err := syncCreatedSpaceChildren(context.Background(), fix.serverName, rooms, map[string]string{spaceRoomID: "!nsp:hooks.example"}, map[string]bool{spaceRoomID: true}, map[string]*importedAccount{})
		if !errors.Is(err, ErrMissingCreator) {
			t.Fatalf("expected ErrMissingCreator in syncCreatedSpaceChildren, got %v", err)
		}
	})
}

func TestSignLocalContactsDirectErrors(t *testing.T) {
	t.Parallel()

	fix := setupImportFixture(t, "trust.example")
	if err := Run(context.Background(), fix.cfg, fix.store, nil); err != nil {
		t.Fatalf("Run setup: %v", err)
	}

	sess, err := fix.store.ReadSession(fix.aliceID)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	cli, _, err := matrix.ConnectWithToken(context.Background(), fix.tuwunel.srv.URL, fix.aliceID, sess.AccessToken, nil)
	if err != nil {
		t.Fatalf("ConnectWithToken: %v", err)
	}
	mach, _, err := matrix.NewOlmMachine(context.Background(), cli, nil)
	if err != nil {
		t.Fatalf("NewOlmMachine: %v", err)
	}
	if impErr := mach.ImportCrossSigningKeys(crypto.CrossSigningSeeds{
		MasterKey:      fix.aliceCrypto.identityData.MasterSeed,
		SelfSigningKey: fix.aliceCrypto.identityData.SelfSigningSeed,
		UserSigningKey: fix.aliceCrypto.identityData.UserSigningSeed,
	}); impErr != nil {
		t.Fatalf("ImportCrossSigningKeys: %v", impErr)
	}
	acc := &importedAccount{
		cli:    cli,
		mach:   mach,
		userID: fix.aliceID,
	}

	fix.tuwunel.failRoute(http.MethodPost, "/keys/signatures/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "sign fail")
	fix.tuwunel.mu.Lock()
	fix.tuwunel.users[fix.carolID].MasterKey.Signatures = nil
	fix.tuwunel.mu.Unlock()
	if signErr := signLocalContacts(context.Background(), acc, []dump.TrustedContact{
		{UserID: fix.bobID, MasterKey: fix.bobCrypto.masterPK.PublicKey().String(), Local: true},
	}); signErr != nil {
		t.Fatalf("expected already-signed Bob contact to skip upload cleanly, got %v", signErr)
	}
	if signErr := signLocalContacts(context.Background(), acc, []dump.TrustedContact{
		{UserID: fix.carolID, MasterKey: fix.carolCrypto.masterPK.PublicKey().String(), Local: true},
	}); signErr == nil {
		t.Fatalf("expected SignUser failure")
	}

	fix.tuwunel.mu.Lock()
	fix.tuwunel.routeFailures = nil
	fix.tuwunel.mu.Unlock()
	fix.tuwunel.failRoute(http.MethodPost, "/keys/query", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "query fail")
	if qErr := signLocalContacts(context.Background(), acc, []dump.TrustedContact{
		{UserID: fix.carolID, MasterKey: fix.carolCrypto.masterPK.PublicKey().String(), Local: true},
	}); qErr == nil {
		t.Fatalf("expected QueryKeys failure")
	}
}

func TestImporterSignJSONAndDefaults(t *testing.T) {
	log := zerolog.Nop()

	if _, err := defaultJSONMarshal(make(chan int)); err == nil {
		t.Fatalf("expected defaultJSONMarshal error for unsupported channel value")
	}

	fix := setupImportFixture(t, "signjson.example")
	if err := defaultWriteSession(fix.store, "invalid user", &dump.SessionData{}); err == nil {
		t.Fatalf("expected defaultWriteSession error on invalid user ID")
	}
	if err := defaultRemoveSession(fix.store, "invalid user"); err == nil {
		t.Fatalf("expected defaultRemoveSession error on invalid user ID")
	}

	fix.tuwunel.addExistingUser(fix.aliceID, "pw1", true)
	cli, _, err := matrix.LoginPassword(context.Background(), fix.tuwunel.srv.URL, fix.aliceID, "pw1", matrix.DefaultDeviceDisplayName, &log)
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	mach, _, err := matrix.NewOlmMachine(context.Background(), cli, &log)
	if err != nil {
		t.Fatalf("NewOlmMachine: %v", err)
	}
	mach.CrossSigningKeys = &crypto.CrossSigningKeysCache{
		MasterKey: failingPKSigning{},
	}
	if _, bkErr := ensureTuwunelBackupVersion(context.Background(), cli, mach, fix.aliceID, fix.aliceCrypto.identityData); bkErr == nil {
		t.Fatalf("expected SignJSON failure")
	}
}

func TestImporterManifestHooks(t *testing.T) {
	log := zerolog.Nop()
	fix := setupImportFixture(t, "manifest-hooks.example")
	for i := range fix.cfg.Accounts {
		fix.cfg.Accounts[i].ExistsOnTuwunel = true
		if i < 2 {
			fix.tuwunel.addExistingUser(fix.cfg.Accounts[i].UserID, fix.cfg.Accounts[i].TuwunelPassword, fix.cfg.Accounts[i].Admin)
		}
	}
	orig := writeManifest
	defer func() { writeManifest = orig }()
	writeManifest = failingWriteManifest
	if err := Run(context.Background(), fix.cfg, fix.store, &log); err == nil {
		t.Fatalf("expected rebuildLocalRooms writeManifest failure")
	}

	emptyFix := setupImportFixture(t, "final-manifest.example")
	for i := range emptyFix.cfg.Accounts {
		emptyFix.cfg.Accounts[i].ExistsOnTuwunel = true
		if i < 2 {
			emptyFix.tuwunel.addExistingUser(emptyFix.cfg.Accounts[i].UserID, emptyFix.cfg.Accounts[i].TuwunelPassword, emptyFix.cfg.Accounts[i].Admin)
		}
	}
	if wErr := emptyFix.store.WriteLocalRooms(&dump.LocalRoomsData{}); wErr != nil {
		t.Fatalf("WriteLocalRooms empty: %v", wErr)
	}
	if err := Run(context.Background(), emptyFix.cfg, emptyFix.store, &log); err == nil {
		t.Fatalf("expected final Run writeManifest failure")
	}
}

func TestImporterSessionHooks(t *testing.T) {
	log := zerolog.Nop()
	fix := setupImportFixture(t, "sess-hooks.example")
	manifest, err := fix.store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	manifest.ProvisionedUsers = make(map[string]bool)

	origWriteSess := writeSession
	defer func() { writeSession = origWriteSess }()
	writeSession = failingWriteSession
	if _, regErr := authenticateTuwunelAccount(context.Background(), fix.cfg, fix.store, manifest, &fix.cfg.Accounts[0], &log); regErr == nil {
		t.Fatalf("expected register saveSession failure")
	}
	if _, logErr := authenticateTuwunelAccount(context.Background(), fix.cfg, fix.store, manifest, &fix.cfg.Accounts[2], &log); logErr == nil {
		t.Fatalf("expected login saveSession failure")
	}
	writeSession = origWriteSess

	if wErr := fix.store.WriteSession(fix.carolID, &dump.SessionData{
		UserID:        fix.carolID,
		HomeserverURL: fix.tuwunel.srv.URL,
	}); wErr != nil {
		t.Fatalf("WriteSession seed: %v", wErr)
	}
	origRemoveSess := removeSession
	defer func() { removeSession = origRemoveSess }()
	removeSession = failingRemoveSession
	if remErr := cleanupPriorSession(context.Background(), fix.tuwunel.srv.URL, fix.store, fix.carolID, &log); remErr == nil {
		t.Fatalf("expected removeSession failure")
	}
}

type failingPKSigning struct {
	olm.PKSigning
}

func (failingPKSigning) SignJSON(_ any) (string, error) {
	return "", errors.New("mock sign json failure")
}

func failingWriteManifest(_ *dump.Store, _ *dump.ManifestState) error {
	return errors.New("mock write manifest failure")
}

func failingWriteSession(_ *dump.Store, _ string, _ *dump.SessionData) error {
	return errors.New("mock write session failure")
}

func failingRemoveSession(_ *dump.Store, _ string) error {
	return errors.New("mock remove session failure")
}

func failingNewOlmMachine(_ context.Context, _ *mautrix.Client, _ *zerolog.Logger) (*crypto.OlmMachine, *mautrix.MemoryStateStore, error) {
	return nil, nil, errors.New("olm init failure")
}

func failingJoinRoomByID(_ context.Context, _ *mautrix.Client, _ id.RoomID) (*mautrix.RespJoinRoom, error) {
	return nil, errors.New("join failure")
}
