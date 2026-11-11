package exporter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/classifier"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

func baseTestConfig(serverName, synapseURL, dumpDir string, accounts ...config.AccountConfig) *config.Config {
	return &config.Config{
		ServerName:       serverName,
		SynapseURL:       synapseURL,
		TuwunelURL:       "http://127.0.0.1:6167",
		DataDir:          dumpDir,
		LocalRoomVersion: "12",
		Accounts:         accounts,
	}
}

type endToEndFixture struct {
	syn          *mockSynapse
	aliceKeys    *testCryptoBundle
	bobKeys      *testCryptoBundle
	aliceAcc     *mockAccountData
	bobAcc       *mockAccountData
	aliceID      id.UserID
	bobID        id.UserID
	carolExt     id.UserID
	botUser      id.UserID
	localRoomID  id.RoomID
	fedRoomID    id.RoomID
	bridgeRoomID id.RoomID
	avatarBytes  []byte
}

func setupEndToEndFixture(t *testing.T) *endToEndFixture {
	t.Helper()
	syn := newMockSynapse()
	t.Cleanup(syn.close)

	f := &endToEndFixture{
		syn:          syn,
		aliceID:      "@alice:example.com",
		bobID:        "@bob:example.com",
		carolExt:     "@carol:partner.example.org",
		botUser:      "@tgbot:example.com",
		localRoomID:  "!local1:example.com",
		fedRoomID:    "!fed1:partner.example.org",
		bridgeRoomID: "!bridge1:example.com",
		avatarBytes:  []byte("png-avatar-alice"),
	}

	f.aliceKeys = newTestCryptoBundle(t, true)
	f.bobKeys = newTestCryptoBundle(t, true)
	carolKeys := newTestCryptoBundle(t, false)

	f.aliceAcc = syn.registerAccount(f.aliceID, "", "alice-tok-1", f.aliceKeys)
	f.bobAcc = syn.registerAccount(f.bobID, "bob-pass-1", "bob-tok-unused", f.bobKeys)

	syn.masterKeys[f.bobID] = signMasterKeyByOwner(t, f.bobID, f.bobKeys.masterPub, f.aliceID, f.aliceKeys.userSigner)
	syn.masterKeys[f.carolExt] = signMasterKeyByOwner(t, f.carolExt, carolKeys.masterPub, f.aliceID, f.aliceKeys.userSigner)
	syn.queryFails["offline.example.net"] = map[string]any{"err": "timeout"}

	_, aliceSessID, aliceEncSess := createTestMegolmSession(t, f.aliceKeys)
	_, bobSessID, bobEncSess := createTestMegolmSession(t, f.bobKeys)

	f.aliceAcc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
		Version:   "v1",
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  backup.MegolmAuthData{PublicKey: f.aliceKeys.backupPub},
	}
	f.aliceAcc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
		Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			f.localRoomID:  {Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{aliceSessID: {IsVerified: true, SessionData: aliceEncSess}}},
			f.bridgeRoomID: {Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{aliceSessID: {SessionData: aliceEncSess}}},
		},
	}

	f.bobAcc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
		Version:   "v2",
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  backup.MegolmAuthData{PublicKey: f.bobKeys.backupPub},
	}
	f.bobAcc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
		Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			f.fedRoomID: {Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{bobSessID: {SessionData: bobEncSess}}},
		},
	}

	syn.media["example.com/aliceav"] = mockMediaItem{data: f.avatarBytes, contentType: "image/png"}
	syn.media["example.com/roomav"] = mockMediaItem{data: []byte("png-room-avatar"), contentType: "", legacyOnly: true}

	f.aliceAcc.profile = &mautrix.RespUserProfile{
		DisplayName: "Alice A",
		AvatarURL:   id.ContentURI{Homeserver: "example.com", FileID: "aliceav"},
	}
	f.aliceAcc.accountData[event.AccountDataDirectChats.Type] = mustJSON(t, &event.DirectChatsEventContent{
		f.bobID:    {f.localRoomID},
		f.botUser:  {f.bridgeRoomID},
		f.carolExt: {f.fedRoomID},
	})
	f.aliceAcc.accountData[event.AccountDataIgnoredUserList.Type] = json.RawMessage(`{"ignored_users":{"@spam:spam.example":{}}}`)

	f.aliceAcc.joinedRooms = []id.RoomID{f.localRoomID, f.fedRoomID, f.bridgeRoomID}
	f.bobAcc.joinedRooms = []id.RoomID{f.localRoomID, f.fedRoomID}

	f.aliceAcc.tagsByRoom[f.localRoomID] = map[event.RoomTag]event.TagMetadata{
		event.RoomTagFavourite: {Order: json.Number("0.25")},
	}
	f.aliceAcc.tagsByRoom[f.bridgeRoomID] = map[event.RoomTag]event.TagMetadata{
		event.RoomTagLowPriority: {},
	}
	f.bobAcc.tagsByRoom[f.bridgeRoomID] = map[event.RoomTag]event.TagMetadata{
		event.RoomTagFavourite: {},
	}

	syn.roomStates[f.localRoomID] = []*event.Event{
		makeCreateEvt(t, f.aliceID),
		makeJoinEvt(t, f.aliceID),
		makeJoinEvt(t, f.bobID),
		makeStateEvt(t, event.StateRoomName, "", f.aliceID, &event.RoomNameEventContent{Name: "Family Room"}),
		makeStateEvt(t, event.StateRoomAvatar, "", f.aliceID, &event.RoomAvatarEventContent{
			URL:  "mxc://example.com/roomav",
			Info: &event.FileInfo{MimeType: "image/webp"},
		}),
		makeStateEvt(t, event.StateEncryption, "", f.aliceID, &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}),
	}
	syn.roomStates[f.fedRoomID] = []*event.Event{
		makeCreateEvt(t, f.carolExt),
		makeJoinEvt(t, f.aliceID),
		makeJoinEvt(t, f.bobID),
		makeJoinEvt(t, f.carolExt),
	}
	syn.roomStates[f.bridgeRoomID] = []*event.Event{
		makeCreateEvt(t, f.botUser),
		makeStateEvt(t, event.StateBridge, "", f.botUser, &event.BridgeEventContent{}),
		makeJoinEvt(t, f.aliceID),
		makeJoinEvt(t, f.botUser),
	}
	return f
}

func TestRunEndToEndMultiAccountAndDeltaManifest(t *testing.T) {
	f := setupEndToEndFixture(t)

	origNow := nowUTC
	t.Cleanup(func() { nowUTC = origNow })
	nowUTC = func() time.Time {
		return time.Date(2026, 11, 9, 20, 0, 0, 0, time.UTC)
	}

	dumpDir := filepath.Join(t.TempDir(), "dump")
	store, err := dump.Open(dumpDir)
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	if seedErr := store.WriteManifest(&dump.ManifestState{
		LocalRoomMap:           map[string]string{"!prior:example.com": "!mapped"},
		ProvisionedUsers:       map[string]bool{f.aliceID.String(): true},
		ServerSigningKeyID:     "ed25519:a_SEED1",
		ServerSigningPublicKey: "seedPubKeyBase64Value",
	}); seedErr != nil {
		t.Fatalf("seed manifest: %v", seedErr)
	}

	cfg := baseTestConfig(
		"example.com",
		f.syn.server.URL,
		dumpDir,
		config.AccountConfig{
			UserID:             f.aliceID.String(),
			SynapseAccessToken: "alice-tok-1",
			RecoveryKey:        f.aliceKeys.recoveryKey,
			Admin:              true,
		},
		config.AccountConfig{
			UserID:          f.bobID.String(),
			SynapsePassword: "bob-pass-1",
			RecoveryKey:     f.bobKeys.recoveryKey,
		},
	)

	var logBuf bytes.Buffer
	log := zerolog.New(&logBuf)
	if runErr := Run(context.Background(), cfg, store, &log); runErr != nil {
		t.Fatalf("Run failed: %v", runErr)
	}

	logOut := logBuf.String()
	if !strings.Contains(logOut, "Excluded Synapse room from migration") || !strings.Contains(logOut, f.bridgeRoomID.String()) {
		t.Errorf("expected excluded room warning in export log, got: %s", logOut)
	}

	assertEndToEndOutputs(t, store, f)
}

func assertEndToEndOutputs(t *testing.T, store *dump.Store, f *endToEndFixture) {
	t.Helper()

	if f.aliceAcc.logoutCount != 0 || f.bobAcc.logoutCount != 1 {
		t.Errorf("logout counts = (%d, %d), want (0, 1)", f.aliceAcc.logoutCount, f.bobAcc.logoutCount)
	}

	assertEndToEndManifestAndIdentity(t, store, f)
	assertEndToEndProfileAndKeys(t, store, f)
	assertEndToEndRoomsAndTrust(t, store, f)
}

func assertEndToEndManifestAndIdentity(t *testing.T, store *dump.Store, f *endToEndFixture) {
	t.Helper()

	gotManifest, err := store.ReadManifest()
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if gotManifest.Phase != dump.PhaseExported || gotManifest.ExportedAt != "2026-11-09T20:00:00Z" {
		t.Errorf("manifest = %+v", gotManifest)
	}
	if gotManifest.LocalRoomMap["!prior:example.com"] != "!mapped" || !gotManifest.ProvisionedUsers[f.aliceID.String()] {
		t.Errorf("delta manifest maps lost: %+v", gotManifest)
	}
	if gotManifest.ServerSigningKeyID != "ed25519:a_SEED1" || gotManifest.ServerSigningPublicKey != "seedPubKeyBase64Value" {
		t.Errorf("server signing key metadata lost: %+v", gotManifest)
	}

	gotIdentity, err := store.ReadIdentity(f.aliceID.String())
	if err != nil {
		t.Fatalf("ReadIdentity: %v", err)
	}
	if gotIdentity.MasterPublicKey != f.aliceKeys.masterPub.String() || len(gotIdentity.RawSSSSAccountData) != 6 {
		t.Errorf("identity mismatch: pub=%s ssssLen=%d", gotIdentity.MasterPublicKey, len(gotIdentity.RawSSSSAccountData))
	}
}

func assertEndToEndProfileAndKeys(t *testing.T, store *dump.Store, f *endToEndFixture) {
	t.Helper()

	gotProfile, err := store.ReadProfile(f.aliceID.String())
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	avSum := sha256.Sum256(f.avatarBytes)
	if gotProfile.DisplayName != "Alice A" || gotProfile.Avatar == nil || gotProfile.Avatar.SHA256 != hex.EncodeToString(avSum[:]) {
		t.Fatalf("profile mismatch: %+v", gotProfile)
	}
	if _, hasBot := gotProfile.Direct[f.botUser.String()]; hasBot {
		t.Errorf("bridge bot should be stripped from m.direct: %+v", gotProfile.Direct)
	}
	if _, hasBridgeTag := gotProfile.RoomTags[f.bridgeRoomID.String()]; hasBridgeTag {
		t.Errorf("bridge room tags should be stripped: %+v", gotProfile.RoomTags)
	}

	bobProfile, err := store.ReadProfile(f.bobID.String())
	if err != nil {
		t.Fatalf("ReadProfile bob: %v", err)
	}
	if bobProfile.RoomTags != nil {
		t.Errorf("expected bob bridge-only room tags stripped to nil, got %+v", bobProfile.RoomTags)
	}

	gotKeys, err := store.ReadRoomKeys(f.aliceID.String())
	if err != nil {
		t.Fatalf("ReadRoomKeys: %v", err)
	}
	if _, hasBridgeKeys := gotKeys.Rooms[f.bridgeRoomID.String()]; hasBridgeKeys || len(gotKeys.Rooms[f.localRoomID.String()].Sessions) != 1 {
		t.Errorf("room keys mismatch: %+v", gotKeys.Rooms)
	}
}

func assertEndToEndRoomsAndTrust(t *testing.T, store *dump.Store, f *endToEndFixture) {
	t.Helper()

	gotTrust, err := store.ReadTrustGraph(f.aliceID.String())
	if err != nil {
		t.Fatalf("ReadTrustGraph: %v", err)
	}
	if len(gotTrust.Contacts) != 2 || gotTrust.Contacts[0].UserID != f.bobID.String() || !gotTrust.Contacts[0].Local || gotTrust.Contacts[1].UserID != f.carolExt.String() || gotTrust.Contacts[1].Local {
		t.Errorf("trust contacts = %+v", gotTrust.Contacts)
	}

	localRooms, err := store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	if len(localRooms.Rooms) != 1 || localRooms.Rooms[0].Avatar == nil || localRooms.Rooms[0].Avatar.ContentType != "image/webp" || !localRooms.Rooms[0].IsDirect {
		t.Errorf("localRooms = %+v", localRooms.Rooms)
	}

	fedRooms, err := store.ReadFederatedRooms()
	if err != nil {
		t.Fatalf("ReadFederatedRooms: %v", err)
	}
	if len(fedRooms.Rooms) != 1 || !slices.Equal(fedRooms.Rooms[0].ViaServers, []string{"partner.example.org"}) {
		t.Errorf("fedRooms = %+v", fedRooms.Rooms)
	}
}

func TestRunValidationAndEarlyErrors(t *testing.T) {
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	syn := newMockSynapse()
	defer syn.close()

	validAcc := config.AccountConfig{
		UserID:          "@alice:beta.example.net",
		SynapsePassword: "pw",
		RecoveryKey:     "EsT123",
	}

	if runErr := Run(context.Background(), nil, store, nil); !errors.Is(runErr, ErrNilConfig) {
		t.Errorf("Run nil cfg = %v, want ErrNilConfig", runErr)
	}
	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root(), validAcc), nil, nil); !errors.Is(runErr, ErrNilStore) {
		t.Errorf("Run nil store = %v, want ErrNilStore", runErr)
	}
	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root()), store, nil); !errors.Is(runErr, config.ErrNoAccounts) {
		t.Errorf("Run invalid cfg = %v, want ErrNoAccounts", runErr)
	}

	manifestPath := filepath.Join(store.Root(), "manifest_state.json")
	if wErr := os.WriteFile(manifestPath, []byte("{corrupt"), 0o600); wErr != nil {
		t.Fatalf("write corrupt manifest: %v", wErr)
	}
	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root(), validAcc), store, nil); runErr == nil {
		t.Errorf("expected error for corrupt existing manifest")
	}
	if remErr := os.Remove(manifestPath); remErr != nil {
		t.Fatalf("remove manifest: %v", remErr)
	}

	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root(), validAcc), store, nil); runErr == nil {
		t.Errorf("expected login error for unregistered user")
	}

	b := newTestCryptoBundle(t, false)
	aliceAcc := syn.registerAccount("@alice:beta.example.net", "pw", "bad-whoami-tok", b)
	aliceAcc.whoamiOverride = "@someoneelse:beta.example.net"
	tokAcc := config.AccountConfig{
		UserID:             "@alice:beta.example.net",
		SynapseAccessToken: "bad-whoami-tok",
		RecoveryKey:        b.recoveryKey,
	}
	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root(), tokAcc), store, nil); runErr == nil {
		t.Errorf("expected whoami mismatch error")
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	aliceAcc.whoamiOverride = ""
	if runErr := Run(canceledCtx, baseTestConfig("beta.example.net", syn.server.URL, store.Root(), validAcc), store, nil); runErr == nil {
		t.Errorf("expected canceled context error during login")
	}

	aliceAcc.backupVerErr = http.StatusNotFound
	nopLog := zerolog.Nop()
	if writeErr := store.WriteManifest(&dump.ManifestState{}); writeErr != nil {
		t.Fatalf("write empty manifest: %v", writeErr)
	}
	validAcc.RecoveryKey = b.recoveryKey
	if runErr := Run(context.Background(), baseTestConfig("beta.example.net", syn.server.URL, store.Root(), validAcc), store, &nopLog); runErr != nil {
		t.Errorf("Run without key backup or existing nil maps = %v", runErr)
	}
}

func TestCryptoVerificationErrors(t *testing.T) {
	tests := []struct {
		setup   func(t *testing.T, syn *mockSynapse, uid id.UserID, acc *mockAccountData, b *testCryptoBundle, cfg *config.AccountConfig)
		wantErr error
		name    string
		wantOK  bool
	}{
		{
			name: "missing default SSSS key returns error",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				delete(acc.accountData, event.AccountDataSecretStorageDefaultKey.Type)
			},
		},
		{
			name: "empty SSSS default key ID returns ErrNoKeyFieldInAccountDataEvent",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.accountData[event.AccountDataSecretStorageDefaultKey.Type] = mustJSON(t, &ssss.DefaultSecretStorageKeyContent{KeyID: ""})
			},
			wantErr: ssss.ErrNoKeyFieldInAccountDataEvent,
		},
		{
			name: "wrong recovery key rejected by SSSS MAC",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, _ *mockAccountData, _ *testCryptoBundle, cfg *config.AccountConfig) {
				cfg.RecoveryKey = "EsTBadRecoveryKey"
			},
		},
		{
			name: "unverifiable key without MAC succeeds via AEAD decryption",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				noMAC := *b.ssssKey.Metadata
				noMAC.MAC = ""
				noMAC.IV = ""
				acc.accountData[event.AccountDataSecretStorageKey.Type+"."+b.defaultKeyID] = mustJSON(t, &noMAC)
			},
			wantOK: true,
		},
		{
			name: "corrupt SSSS cross-signing payload fails decryption",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.accountData[event.AccountDataCrossSigningMaster.Type] = json.RawMessage(`{"encrypted":{}}`)
			},
		},
		{
			name: "keys query error fails cross-signing verification",
			setup: func(_ *testing.T, syn *mockSynapse, _ id.UserID, _ *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				syn.queryErr = http.StatusInternalServerError
			},
		},
		{
			name: "server public key mismatch returns ErrCrossSigningMismatch",
			setup: func(_ *testing.T, syn *mockSynapse, uid id.UserID, _ *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				syn.masterKeys[uid] = mautrix.CrossSigningKeys{
					UserID: uid,
					Keys:   map[id.KeyID]id.Ed25519{"ed25519:wrong": "wrong-pub"},
				}
			},
			wantErr: ErrCrossSigningMismatch,
		},
		{
			name: "non-404 backup key decryption error fails export",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.accountData[event.AccountDataMegolmBackupKey.Type] = json.RawMessage(`{"encrypted":{}}`)
			},
		},
		{
			name: "server backup exists while SSSS missing m.megolm_backup.v1 returns ErrMissingBackupKey",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				delete(acc.accountData, event.AccountDataMegolmBackupKey.Type)
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v9",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
			},
			wantErr: ErrMissingBackupKey,
		},
		{
			name: "missing SSSS key plus 500 on version check returns error",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				delete(acc.accountData, event.AccountDataMegolmBackupKey.Type)
				acc.backupVerErr = http.StatusInternalServerError
			},
		},
		{
			name: "malformed megolm backup key bytes fail parsing",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				acc.accountData[event.AccountDataMegolmBackupKey.Type] = encryptSSSSRaw(t, b.ssssKey, event.AccountDataMegolmBackupKey.Type, []byte("too-short"))
			},
		},
		{
			name: "SSSS has backup key while Synapse returns 404 skips room_keys cleanly",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVersion = nil
			},
			wantOK: true,
		},
		{
			name: "version endpoint 500 fails export",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVerErr = http.StatusInternalServerError
			},
		},
		{
			name: "unsupported backup algorithm returns ErrUnsupportedBackupAlg",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithm("m.unknown.backup"),
				}
			},
			wantErr: ErrUnsupportedBackupAlg,
		},
		{
			name: "backup pubkey mismatch returns ErrBackupKeyMismatch",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: "mismatch-pub"},
				}
			},
			wantErr: ErrBackupKeyMismatch,
		},
		{
			name: "GetKeyBackup 500 error fails export",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
				acc.roomKeysErr = http.StatusInternalServerError
			},
		},
		{
			name: "backup session decrypt MAC failure returns ErrBackupCorrupted",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				otherKey := newTestCryptoBundle(t, true)
				_, sessID, encSess := createTestMegolmSession(t, otherKey)
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
				acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
						"!empty:gamma.example.org": {},
						"!zbad:gamma.example.org": {
							Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
								sessID: {SessionData: encSess},
							},
						},
					},
				}
			},
			wantErr: ErrBackupCorrupted,
		},
		{
			name: "backup with only empty room session maps succeeds cleanly",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
				acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
						"!emptyonly:gamma.example.org": {},
					},
				}
			},
			wantOK: true,
		},
		{
			name: "verbatim SSSS copy 500 after cross-signing fetch returns error",
			setup: func(_ *testing.T, syn *mockSynapse, _ id.UserID, _ *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				var reads atomic.Int32
				oldHandler := syn.server.Config.Handler
				syn.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/account_data/"+event.AccountDataCrossSigningUser.Type) && reads.Add(1) > 1 {
						writeJSONError(w, http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "verbatim fetch err")
						return
					}
					oldHandler.ServeHTTP(w, r)
				})
			},
		},
		{
			name: "backup session corrupt SessionKey returns ErrBackupCorrupted",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				encSess, err := backup.EncryptSessionData(b.backupKey, backup.MegolmSessionData{
					Algorithm:  id.AlgorithmMegolmV1,
					SenderKey:  b.senderCurveKey,
					SessionKey: "not-valid-exported-session",
				})
				if err != nil {
					t.Fatalf("EncryptSessionData: %v", err)
				}
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
				acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
						"!badkey:gamma.example.org": {
							Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
								"sess1": {SessionData: encSess},
							},
						},
					},
				}
			},
			wantErr: ErrBackupCorrupted,
		},
		{
			name: "backup session ID mismatch returns ErrBackupCorrupted",
			setup: func(t *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, b *testCryptoBundle, _ *config.AccountConfig) {
				_, _, encSess := createTestMegolmSession(t, b)
				acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
					Version:   "v1",
					Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
					AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
				}
				acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
						"!mismatch:gamma.example.org": {
							Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
								"wrong-sess-id": {SessionData: encSess},
							},
						},
					},
				}
			},
			wantErr: ErrBackupCorrupted,
		},
		{
			name: "missing raw SSSS key during verbatim copy returns error",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData, _ *testCryptoBundle, _ *config.AccountConfig) {
				acc.accountData = map[string]json.RawMessage{
					event.AccountDataSecretStorageDefaultKey.Type: acc.accountData[event.AccountDataSecretStorageDefaultKey.Type],
				}
			},
		},
	}

	for idx, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			syn := newMockSynapse()
			defer syn.close()

			uid := id.UserID(fmt.Sprintf("@user%d:gamma.example.org", idx))
			b := newTestCryptoBundle(t, true)
			acc := syn.registerAccount(uid, "pw", "tok", b)
			cfgAcc := config.AccountConfig{
				UserID:          uid.String(),
				SynapsePassword: "pw",
				RecoveryKey:     b.recoveryKey,
			}
			tc.setup(t, syn, uid, acc, b, &cfgAcc)

			store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			log := zerolog.Nop()
			runErr := Run(context.Background(), baseTestConfig("gamma.example.org", syn.server.URL, store.Root(), cfgAcc), store, &log)

			if tc.wantOK {
				if runErr != nil {
					t.Fatalf("unexpected error: %v", runErr)
				}
				return
			}
			if runErr == nil {
				t.Fatalf("expected error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(runErr, tc.wantErr) {
				t.Errorf("err = %v, want %v", runErr, tc.wantErr)
			}
		})
	}
}

func TestRoomsProfileMediaTrustEdgeCases(t *testing.T) {
	syn := newMockSynapse()
	defer syn.close()

	uid := id.UserID("@alice:delta.example")
	peerUID := id.UserID("@peer:delta.example")
	ghostUID := id.UserID("@ghost:delta.example")
	extGood := id.UserID("@ext:partner.example.org")
	svcBot := id.UserID("@service:delta.example")

	b := newTestCryptoBundle(t, false)
	bPeer := newTestCryptoBundle(t, false)
	bGhost := newTestCryptoBundle(t, false)

	acc := syn.registerAccount(uid, "pw", "tok", b)
	peerAcc := syn.registerAccount(peerUID, "pw", "tok-peer", bPeer)
	ghostAcc := syn.registerAccount(ghostUID, "pw", "tok-ghost", bGhost)

	acc.profileErr = http.StatusNotFound
	peerAcc.profile = &mautrix.RespUserProfile{DisplayName: "Peer No Avatar"}
	ghostAcc.profile = &mautrix.RespUserProfile{
		DisplayName: "Ghost Missing Avatar",
		AvatarURL:   id.ContentURI{Homeserver: "delta.example", FileID: "missing-user-av"},
	}

	missingAvRoom := id.RoomID("!av404:delta.example")
	badURIRoom := id.RoomID("!baduri:delta.example")
	funcBridgeRoom := id.RoomID("!funcbridge:delta.example")
	allowFuncRoom := id.RoomID("!allowfunc:delta.example")
	badFuncRoom := id.RoomID("!badfunc:delta.example")
	noContentRoom := id.RoomID("!nocontent:delta.example")

	acc.joinedRooms = []id.RoomID{missingAvRoom, badURIRoom, funcBridgeRoom, allowFuncRoom, badFuncRoom, noContentRoom}
	acc.tagsByRoom[missingAvRoom] = map[event.RoomTag]event.TagMetadata{}
	peerAcc.joinedRooms = []id.RoomID{funcBridgeRoom}
	peerAcc.tagsByRoom[funcBridgeRoom] = map[event.RoomTag]event.TagMetadata{event.RoomTagFavourite: {}}
	emptyKey := ""

	syn.roomStates[missingAvRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeStateEvt(t, event.StateRoomAvatar, "", uid, &event.RoomAvatarEventContent{URL: "mxc://delta.example/missing404"}),
	}
	syn.roomStates[badURIRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeStateEvt(t, event.StateRoomAvatar, "", uid, &event.RoomAvatarEventContent{URL: "not-an-mxc-uri"}),
	}
	syn.roomStates[funcBridgeRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeJoinEvt(t, peerUID),
		makeJoinEvt(t, extGood),
		makeStateEvt(t, event.StateElementFunctionalMembers, "", uid, &event.ElementFunctionalMembersContent{ServiceMembers: []id.UserID{svcBot}}),
	}
	syn.roomStates[allowFuncRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeJoinEvt(t, extGood),
		makeStateEvt(t, event.StateElementFunctionalMembers, "", uid, &event.ElementFunctionalMembersContent{ServiceMembers: []id.UserID{uid}}),
	}
	syn.roomStates[badFuncRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		{
			Type:     event.StateElementFunctionalMembers,
			StateKey: &emptyKey,
			Sender:   uid,
			Content:  event.Content{VeryRaw: json.RawMessage(`{"service_members":"not-a-slice"}`)},
		},
	}

	syn.rawRoomStates[noContentRoom] = json.RawMessage(`[{"type":"m.room.topic","state_key":"","sender":"@alice:delta.example"}]`)
	syn.queryHook = func(req *mautrix.ReqQueryKeys) (*mautrix.RespQueryKeys, int) {
		_, hasPeer := req.DeviceKeys[peerUID]
		_, hasGhost := req.DeviceKeys[ghostUID]
		if hasPeer && hasGhost {
			return &mautrix.RespQueryKeys{
				MasterKeys: map[id.UserID]mautrix.CrossSigningKeys{
					peerUID: {
						UserID: peerUID,
						Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
						Keys:   map[id.KeyID]id.Ed25519{},
					},
				},
			}, http.StatusOK
		}
		return nil, 0
	}

	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	log := zerolog.Nop()
	if runErr := Run(
		context.Background(),
		baseTestConfig(
			"delta.example",
			syn.server.URL,
			store.Root(),
			config.AccountConfig{UserID: uid.String(), SynapsePassword: "pw", RecoveryKey: b.recoveryKey},
			config.AccountConfig{UserID: peerUID.String(), SynapsePassword: "pw", RecoveryKey: bPeer.recoveryKey},
			config.AccountConfig{UserID: ghostUID.String(), SynapsePassword: "pw", RecoveryKey: bGhost.recoveryKey},
		),
		store,
		&log,
	); runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}

	gotPeerProf, err := store.ReadProfile(peerUID.String())
	if err != nil {
		t.Fatalf("ReadProfile peer: %v", err)
	}
	if gotPeerProf.DisplayName != "Peer No Avatar" || gotPeerProf.Avatar != nil {
		t.Errorf("peer profile = %+v", gotPeerProf)
	}

	gotGhostProf, err := store.ReadProfile(ghostUID.String())
	if err != nil {
		t.Fatalf("ReadProfile ghost: %v", err)
	}
	if gotGhostProf.DisplayName != "Ghost Missing Avatar" || gotGhostProf.Avatar != nil {
		t.Errorf("ghost profile = %+v", gotGhostProf)
	}
}

func TestRoomsProfileMediaFailures(t *testing.T) {
	failureCases := []struct {
		setup func(t *testing.T, syn *mockSynapse, uid id.UserID, acc *mockAccountData) []config.AccountConfig
		name  string
	}{
		{
			name: "profile endpoint 500",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				acc.profileErr = http.StatusInternalServerError
				return nil
			},
		},
		{
			name: "user avatar 500 download",
			setup: func(_ *testing.T, syn *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				acc.profile = &mautrix.RespUserProfile{AvatarURL: id.ContentURI{Homeserver: "epsilon.example", FileID: "fail500"}}
				syn.media["epsilon.example/fail500"] = mockMediaItem{statusErr: http.StatusInternalServerError}
				return nil
			},
		},
		{
			name: "m.direct invalid JSON fails",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				acc.accountData[event.AccountDataDirectChats.Type] = json.RawMessage(`"not-map"`)
				return nil
			},
		},
		{
			name: "m.ignored_user_list endpoint 500",
			setup: func(_ *testing.T, _ *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				acc.accountDataErr[event.AccountDataIgnoredUserList.Type] = http.StatusInternalServerError
				return nil
			},
		},
		{
			name: "joined rooms endpoint 500",
			setup: func(_ *testing.T, syn *mockSynapse, _ id.UserID, _ *mockAccountData) []config.AccountConfig {
				syn.joinedErr = http.StatusInternalServerError
				return nil
			},
		},
		{
			name: "room state endpoint 500",
			setup: func(_ *testing.T, syn *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				acc.joinedRooms = []id.RoomID{"!errstate:epsilon.example"}
				syn.roomStateErr = http.StatusInternalServerError
				return nil
			},
		},
		{
			name: "room tags endpoint 500",
			setup: func(t *testing.T, syn *mockSynapse, uid id.UserID, acc *mockAccountData) []config.AccountConfig {
				rid := id.RoomID("!errtag:epsilon.example")
				acc.joinedRooms = []id.RoomID{rid}
				syn.roomStates[rid] = []*event.Event{makeJoinEvt(t, uid)}
				acc.tagErrStatus = http.StatusInternalServerError
				return nil
			},
		},
		{
			name: "room avatar 500 download",
			setup: func(t *testing.T, syn *mockSynapse, uid id.UserID, acc *mockAccountData) []config.AccountConfig {
				rid := id.RoomID("!errav:epsilon.example")
				acc.joinedRooms = []id.RoomID{rid}
				syn.roomStates[rid] = []*event.Event{
					makeJoinEvt(t, uid),
					makeStateEvt(t, event.StateRoomAvatar, "", uid, &event.RoomAvatarEventContent{URL: "mxc://epsilon.example/failroomav"}),
				}
				syn.media["epsilon.example/failroomav"] = mockMediaItem{statusErr: http.StatusInternalServerError}
				return nil
			},
		},
		{
			name: "local trust query error",
			setup: func(t *testing.T, syn *mockSynapse, _ id.UserID, _ *mockAccountData) []config.AccountConfig {
				helperUID := id.UserID("@helperlocal:epsilon.example")
				hb := newTestCryptoBundle(t, false)
				syn.registerAccount(helperUID, "pw", "tok-h", hb)
				syn.queryHook = func(req *mautrix.ReqQueryKeys) (*mautrix.RespQueryKeys, int) {
					if _, exists := req.DeviceKeys[helperUID]; exists {
						return nil, http.StatusInternalServerError
					}
					return nil, 0
				}
				return []config.AccountConfig{{
					UserID:          helperUID.String(),
					SynapsePassword: "pw",
					RecoveryKey:     hb.recoveryKey,
				}}
			},
		},
		{
			name: "external trust query error",
			setup: func(t *testing.T, syn *mockSynapse, _ id.UserID, acc *mockAccountData) []config.AccountConfig {
				remoteUID := id.UserID("@remote:partner.example.org")
				acc.accountData[event.AccountDataDirectChats.Type] = mustJSON(t, &event.DirectChatsEventContent{
					remoteUID: {"!dmext:epsilon.example"},
				})
				_ = syn.registerAccount("@helper:epsilon.example", "p", "t", newTestCryptoBundle(t, false))
				syn.queryHook = func(req *mautrix.ReqQueryKeys) (*mautrix.RespQueryKeys, int) {
					if _, exists := req.DeviceKeys[remoteUID]; exists {
						return nil, http.StatusInternalServerError
					}
					return nil, 0
				}
				return nil
			},
		},
	}

	for _, fc := range failureCases {
		t.Run(fc.name, func(t *testing.T) {
			syn := newMockSynapse()
			defer syn.close()

			uid := id.UserID("@alice:epsilon.example")
			b := newTestCryptoBundle(t, false)
			acc := syn.registerAccount(uid, "pw", "tok", b)
			extraAccs := fc.setup(t, syn, uid, acc)

			accs := append([]config.AccountConfig{{
				UserID:          uid.String(),
				SynapsePassword: "pw",
				RecoveryKey:     b.recoveryKey,
			}}, extraAccs...)

			store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			log := zerolog.Nop()
			runErr := Run(context.Background(), baseTestConfig("epsilon.example", syn.server.URL, store.Root(), accs...), store, &log)
			if runErr == nil {
				t.Errorf("expected error for %s, got nil", fc.name)
			}
		})
	}
}

func TestHelpersAndWriteErrorBranches(t *testing.T) {
	syn := newMockSynapse()
	defer syn.close()

	origMarshal := jsonMarshal
	t.Cleanup(func() { jsonMarshal = origMarshal })

	uid := id.UserID("@alice:zeta.example.net")
	b := newTestCryptoBundle(t, true)
	acc := syn.registerAccount(uid, "pw", "tok", b)
	_, sessID, encSess := createTestMegolmSession(t, b)
	acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
		Version:   "v1",
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
	}
	acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
		Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			"!r1:zeta.example.net": {Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{sessID: {SessionData: encSess}}},
		},
	}

	marshalFail := errors.New("marshal fail")
	jsonMarshal = func(any) ([]byte, error) {
		return nil, marshalFail
	}
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	log := zerolog.Nop()
	if runErr := Run(context.Background(), baseTestConfig("zeta.example.net", syn.server.URL, store.Root(), config.AccountConfig{
		UserID:          uid.String(),
		SynapsePassword: "pw",
		RecoveryKey:     b.recoveryKey,
	}), store, &log); !errors.Is(runErr, marshalFail) {
		t.Errorf("populateRoomKeys marshal err = %v, want %v", runErr, marshalFail)
	}
	jsonMarshal = origMarshal

	if _, mErr := defaultJSONMarshal(make(chan int)); mErr == nil {
		t.Errorf("expected defaultJSONMarshal error for channel")
	}

	writeErrStore, err := dump.Open(filepath.Join(t.TempDir(), "err-dump"))
	if err != nil {
		t.Fatalf("Open err-dump: %v", err)
	}
	if remErr := os.RemoveAll(filepath.Join(writeErrStore.Root(), "rooms")); remErr != nil {
		t.Fatalf("remove rooms: %v", remErr)
	}
	if persistErr := persistExportOutputs(writeErrStore, baseTestConfig("zeta.example.net", syn.server.URL, writeErrStore.Root()), &dump.ManifestState{}, &classifier.Corpus{}, nil, nil, nil); persistErr == nil {
		t.Errorf("expected write local rooms missing directory failure")
	}

	if extractServerName("no-colon") != "" {
		t.Errorf("expected empty server name without colon")
	}

	badPayload := make([]byte, dump.MaxMediaBytes+1)
	if _, randErr := rand.Read(badPayload[:32]); randErr != nil {
		t.Fatalf("rand: %v", randErr)
	}
	syn.media["zeta.example.net/toolarge"] = mockMediaItem{data: badPayload}
	cli, err := mautrix.NewClient(syn.server.URL, uid, "tok")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, dlErr := downloadOptionalMedia(context.Background(), cli, store, id.ContentURI{Homeserver: "zeta.example.net", FileID: "toolarge"}, "", "big.bin", &log); dlErr == nil {
		t.Errorf("expected oversized download error")
	}

	brokenCLI, err := mautrix.NewClient("http://127.0.0.1:1", uid, "tok")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	logoutSynapseSession(context.Background(), brokenCLI, uid.String(), &log)

	if accErr := writeSingleAccountDump(writeErrStore, "zeta.example.net", nil, nil, &exportedAccountState{
		userID: "invalid-user",
		profile: &dump.ProfileData{
			Direct: map[string][]string{"@a:zeta.example.net": {"!r:zeta.example.net"}},
		},
	}); !errors.Is(accErr, validator.ErrInvalidUserID) {
		t.Errorf("writeSingleAccountDump invalid user = %v", accErr)
	}
}

func TestProfileNullAndMediaSaveError(t *testing.T) {
	syn := newMockSynapse()
	defer syn.close()

	uid := id.UserID("@alice:kappa.example")
	acc := syn.registerAccount(uid, "pw", "tok", newTestCryptoBundle(t, false))
	acc.profileNull = true
	syn.media["kappa.example/smallsave"] = mockMediaItem{data: []byte("small-payload")}

	cli, err := mautrix.NewClient(syn.server.URL, uid, "tok")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	store, err := dump.Open(filepath.Join(t.TempDir(), "media-err"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if remErr := os.RemoveAll(filepath.Join(store.Root(), "media")); remErr != nil {
		t.Fatalf("remove media: %v", remErr)
	}

	log := zerolog.Nop()
	if _, _, saveErr := downloadOptionalMedia(context.Background(), cli, store, id.ContentURI{Homeserver: "kappa.example", FileID: "smallsave"}, "", "small.bin", &log); saveErr == nil {
		t.Errorf("expected store.SaveMedia failure")
	}
	if dn, av, profErr := fetchUserProfile(context.Background(), cli, store, uid.String(), &log); profErr != nil || dn != "" || av != nil {
		t.Errorf("fetchUserProfile null response = (%q, %v, %v)", dn, av, profErr)
	}
}

func failNewOlmMachine(_ context.Context, _ *mautrix.Client, _ *zerolog.Logger) (*crypto.OlmMachine, *mautrix.MemoryStateStore, error) {
	return nil, nil, errors.New("olm init boom")
}

func TestWriteAndPersistErrorBranches(t *testing.T) {
	syn := newMockSynapse()
	defer syn.close()

	uid := id.UserID("@alice:iota.example")
	b := newTestCryptoBundle(t, false)
	syn.registerAccount(uid, "pw", "tok", b)

	origNewOlm := newOlmMachine
	t.Cleanup(func() { newOlmMachine = origNewOlm })
	newOlmMachine = failNewOlmMachine

	storeOlm, err := dump.Open(filepath.Join(t.TempDir(), "olm-dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	log := zerolog.Nop()
	if runErr := Run(context.Background(), baseTestConfig("iota.example", syn.server.URL, storeOlm.Root(), config.AccountConfig{
		UserID:          uid.String(),
		SynapsePassword: "pw",
		RecoveryKey:     b.recoveryKey,
	}), storeOlm, &log); runErr == nil || !strings.Contains(runErr.Error(), "init olm machine") {
		t.Errorf("expected init olm machine error, got %v", runErr)
	}
	newOlmMachine = origNewOlm

	runPersistStore, err := dump.Open(filepath.Join(t.TempDir(), "run-persist-err"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if remErr := os.RemoveAll(filepath.Join(runPersistStore.Root(), "rooms")); remErr != nil {
		t.Fatalf("remove rooms: %v", remErr)
	}
	if runErr := Run(context.Background(), baseTestConfig("iota.example", syn.server.URL, runPersistStore.Root(), config.AccountConfig{
		UserID:          uid.String(),
		SynapsePassword: "pw",
		RecoveryKey:     b.recoveryKey,
	}), runPersistStore, &log); runErr == nil {
		t.Errorf("expected persist error from Run")
	}

	writeTargets := []struct {
		name      string
		target    string
		subDir    string
		inAccount bool
	}{
		{name: "WriteRoomKeys failure", inAccount: true, target: "room_keys.json"},
		{name: "WriteProfile failure", inAccount: true, target: "profile.json"},
		{name: "WriteTrustGraph failure", inAccount: true, target: "trust_graph.json"},
		{name: "WriteFederatedRooms failure", subDir: "rooms", target: "federated_rooms.json"},
		{name: "WriteManifest failure", target: "manifest_state.json"},
	}

	for _, wt := range writeTargets {
		t.Run(wt.name, func(t *testing.T) {
			st, stErr := dump.Open(filepath.Join(t.TempDir(), "wt-dump"))
			if stErr != nil {
				t.Fatalf("Open: %v", stErr)
			}
			baseDir := st.Root()
			if wt.inAccount {
				accDir := filepath.Join(st.Root(), "accounts", uid.String())
				if mkErr := os.MkdirAll(accDir, 0o700); mkErr != nil {
					t.Fatalf("MkdirAll accDir: %v", mkErr)
				}
				baseDir = accDir
			} else if wt.subDir != "" {
				baseDir = filepath.Join(baseDir, wt.subDir)
			}
			if mkErr := os.MkdirAll(filepath.Join(baseDir, wt.target, "lock"), 0o700); mkErr != nil {
				t.Fatalf("MkdirAll conflict: %v", mkErr)
			}

			state := &exportedAccountState{
				userID:     uid.String(),
				identity:   &dump.IdentityData{UserID: uid.String()},
				roomKeys:   &dump.RoomKeysData{UserID: uid.String(), Rooms: map[string]dump.RoomKeyBackupRoom{}},
				profile:    &dump.ProfileData{UserID: uid.String()},
				trustGraph: &dump.TrustGraphData{UserID: uid.String()},
			}
			persistErr := persistExportOutputs(
				st,
				baseTestConfig("iota.example", syn.server.URL, st.Root()),
				&dump.ManifestState{},
				&classifier.Corpus{},
				[]*exportedAccountState{state},
				nil,
				nil,
			)
			if persistErr == nil {
				t.Errorf("expected %s", wt.name)
			}
		})
	}
}

type loggedRoomWarning struct {
	Level                    string   `json:"level"`
	RoomID                   string   `json:"room_id"`
	RoomName                 string   `json:"room_name"`
	Reason                   string   `json:"reason"`
	Message                  string   `json:"message"`
	BlockingUsers            []string `json:"blocking_users"`
	JoinedLocalUsers         []string `json:"joined_local_users"`
	ExcludedJoinedLocalUsers []string `json:"excluded_joined_local_users"`
	DepartedLocalUsers       []string `json:"departed_local_users"`
	DepartedExternalUsers    []string `json:"departed_external_users"`
}

func assertSingleRoomWarnJSON(t *testing.T, raw []byte, wantKeyCount int) loggedRoomWarning {
	t.Helper()
	var decoded loggedRoomWarning
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal log json %q: %v", string(raw), err)
	}
	if decoded.Level != "warn" {
		t.Errorf("log level = %q, want warn", decoded.Level)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("unmarshal raw map %q: %v", string(raw), err)
	}
	if len(rawMap) != wantKeyCount {
		t.Errorf("JSON key count = %d, want %d; raw=%v", len(rawMap), wantKeyCount, rawMap)
	}
	return decoded
}

func TestLogExcludedRooms(t *testing.T) {
	tests := []struct {
		name         string
		want         loggedRoomWarning
		excluded     []classifier.ExcludedRoom
		wantKeyCount int
		expectSilent bool
	}{
		{
			name:         "empty excluded list produces no log lines",
			expectSilent: true,
		},
		{
			name: "named room with full diagnostic member lists",
			excluded: []classifier.ExcludedRoom{
				{
					RoomID:                   "!alerts:alpha.example.com",
					RoomName:                 "Monitoring Alerts",
					Reason:                   "room contains non-allowlisted functional service members (io.element.functional_members)",
					BridgeUsers:              []string{"@uptime:alpha.example.com"},
					ExcludedJoinedLocalUsers: []string{"@support:alpha.example.com"},
					DepartedLocalUsers:       []string{"@legacy:alpha.example.com"},
					DepartedExternalUsers:    []string{"@ext:partner.example.org"},
					JoinedLocalUsers:         []string{"@alice:alpha.example.com"},
				},
			},
			wantKeyCount: 10,
			want: loggedRoomWarning{
				RoomID:                   "!alerts:alpha.example.com",
				RoomName:                 "Monitoring Alerts",
				Reason:                   "room contains non-allowlisted functional service members (io.element.functional_members)",
				Message:                  "Excluded Synapse room from migration",
				BlockingUsers:            []string{"@uptime:alpha.example.com"},
				ExcludedJoinedLocalUsers: []string{"@support:alpha.example.com"},
				DepartedLocalUsers:       []string{"@legacy:alpha.example.com"},
				DepartedExternalUsers:    []string{"@ext:partner.example.org"},
				JoinedLocalUsers:         []string{"@alice:alpha.example.com"},
			},
		},
		{
			name: "unnamed orphaned room without optional fields",
			excluded: []classifier.ExcludedRoom{
				{
					RoomID: "!orphan:beta.example.net",
					Reason: "no allowlisted local member is currently joined",
				},
			},
			wantKeyCount: 4,
			want: loggedRoomWarning{
				RoomID:  "!orphan:beta.example.net",
				Reason:  "no allowlisted local member is currently joined",
				Message: "Excluded Synapse room from migration",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := zerolog.New(&buf)
			logExcludedRooms(tc.excluded, &log)

			gotBytes := bytes.TrimSpace(buf.Bytes())
			if tc.expectSilent {
				if len(gotBytes) != 0 {
					t.Errorf("expected empty log output, got %q", string(gotBytes))
				}
				return
			}
			got := assertSingleRoomWarnJSON(t, gotBytes, tc.wantKeyCount)
			assertLoggedRoomWarningEqual(t, &got, &tc.want)
		})
	}
}

func TestLogPartialLocalRooms(t *testing.T) {
	tests := []struct {
		name         string
		want         loggedRoomWarning
		partial      []classifier.PartialLocalRoom
		wantKeyCount int
		expectSilent bool
	}{
		{
			name:         "empty partial list produces no log lines",
			expectSilent: true,
		},
		{
			name: "named partial local room logs all participant categories",
			partial: []classifier.PartialLocalRoom{
				{
					RoomID:                   "!group:gamma.example.org",
					RoomName:                 "Study Group",
					JoinedLocalUsers:         []string{"@alice:gamma.example.org", "@bob:gamma.example.org"},
					ExcludedJoinedLocalUsers: []string{"@teacher:gamma.example.org"},
					DepartedLocalUsers:       []string{"@old:gamma.example.org"},
					DepartedExternalUsers:    []string{"@ext:remote.example.net"},
				},
			},
			wantKeyCount: 8,
			want: loggedRoomWarning{
				RoomID:                   "!group:gamma.example.org",
				RoomName:                 "Study Group",
				Message:                  "Migrated local room excluding non-allowlisted or departed participants",
				JoinedLocalUsers:         []string{"@alice:gamma.example.org", "@bob:gamma.example.org"},
				ExcludedJoinedLocalUsers: []string{"@teacher:gamma.example.org"},
				DepartedLocalUsers:       []string{"@old:gamma.example.org"},
				DepartedExternalUsers:    []string{"@ext:remote.example.net"},
			},
		},
		{
			name: "unnamed partial local room omits unset optional fields",
			partial: []classifier.PartialLocalRoom{
				{
					RoomID: "!minimal:delta.example",
				},
			},
			wantKeyCount: 3,
			want: loggedRoomWarning{
				RoomID:  "!minimal:delta.example",
				Message: "Migrated local room excluding non-allowlisted or departed participants",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := zerolog.New(&buf)
			logPartialLocalRooms(tc.partial, &log)

			gotBytes := bytes.TrimSpace(buf.Bytes())
			if tc.expectSilent {
				if len(gotBytes) != 0 {
					t.Errorf("expected empty log output, got %q", string(gotBytes))
				}
				return
			}
			got := assertSingleRoomWarnJSON(t, gotBytes, tc.wantKeyCount)
			assertLoggedRoomWarningEqual(t, &got, &tc.want)
		})
	}
}

func assertLoggedRoomWarningEqual(t *testing.T, got, want *loggedRoomWarning) {
	t.Helper()
	if got.RoomID != want.RoomID || got.RoomName != want.RoomName || got.Reason != want.Reason || got.Message != want.Message {
		t.Errorf("scalar fields mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
	if !slices.Equal(got.BlockingUsers, want.BlockingUsers) ||
		!slices.Equal(got.JoinedLocalUsers, want.JoinedLocalUsers) ||
		!slices.Equal(got.ExcludedJoinedLocalUsers, want.ExcludedJoinedLocalUsers) ||
		!slices.Equal(got.DepartedLocalUsers, want.DepartedLocalUsers) ||
		!slices.Equal(got.DepartedExternalUsers, want.DepartedExternalUsers) {
		t.Errorf("slice fields mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}
