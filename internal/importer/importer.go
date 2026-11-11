// Package importer provisions Tuwunel accounts, restores cryptographic identities, rebuilds local Room v12 rooms, and replays personal notes.
package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/classifier"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
	"github.com/underhax/synapse-tuwunel-migration/internal/signingkey"
)

const (
	keysQueryTimeoutMs       = 5000
	backupUploadBatchSize    = 200
	roomVersionTwelve        = "12"
	spaceRoomType            = "m.space"
	defaultHistoryVisibility = event.HistoryVisibilityShared
	roomAvatarDefaultMime    = "image/png"
	defaultRoomVisibility    = "private"
)

// Sentinel errors returned when Tuwunel staging import preconditions or cryptographic verification fail.
var (
	ErrNilConfig         = errors.New("config must not be nil")
	ErrNilStore          = errors.New("dump store must not be nil")
	ErrMissingManifest   = errors.New("manifest_state.json missing; run export before import-local")
	ErrMissingCreator    = errors.New("chosen room creator missing from configured accounts")
	ErrMissingMember     = errors.New("room member missing from configured accounts")
	ErrMasterKeyMismatch = errors.New("server master key does not match exported trust graph")
	ErrInvalidLocalSeed  = errors.New("invalid exported cross-signing seed payload")
)

var stateRoomRetention = event.Type{Type: "m.room.retention", Class: event.StateEventType}

func defaultJSONMarshal(v any) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON payload: %w", err)
	}
	return encoded, nil
}

func defaultJoinRoomByID(ctx context.Context, cli *mautrix.Client, roomID id.RoomID) (*mautrix.RespJoinRoom, error) {
	resp, err := cli.JoinRoomByID(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("join room %s: %w", roomID, err)
	}
	return resp, nil
}

func defaultWriteManifest(store *dump.Store, state *dump.ManifestState) error {
	if err := store.WriteManifest(state); err != nil {
		return fmt.Errorf("write manifest_state.json: %w", err)
	}
	return nil
}

func defaultWriteSession(store *dump.Store, userID string, data *dump.SessionData) error {
	if err := store.WriteSession(userID, data); err != nil {
		return fmt.Errorf("write account session: %w", err)
	}
	return nil
}

func defaultRemoveSession(store *dump.Store, userID string) error {
	if err := store.RemoveSession(userID); err != nil {
		return fmt.Errorf("remove account session: %w", err)
	}
	return nil
}

var (
	jsonMarshal   = defaultJSONMarshal
	newOlmMachine = matrix.NewOlmMachine
	joinRoomByID  = defaultJoinRoomByID
	writeManifest = defaultWriteManifest
	writeSession  = defaultWriteSession
	removeSession = defaultRemoveSession
)

type importedAccount struct {
	cli           *mautrix.Client
	mach          *crypto.OlmMachine
	stateStore    *mautrix.MemoryStateStore
	identity      *dump.IdentityData
	profile       *dump.ProfileData
	backupKey     *backup.MegolmBackupKey
	userID        string
	backupVersion string
}

// Run imports identities, key backups, local Room v12 rooms, notes, and internal trust signatures into Tuwunel.
func Run(ctx context.Context, cfg *config.Config, store *dump.Store, log *zerolog.Logger) error {
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
	if err := cfg.ValidateForMode(config.ModeImportLocal); err != nil {
		return fmt.Errorf("validate import-local config: %w", err)
	}

	manifest, err := loadImportManifest(store)
	if err != nil {
		return err
	}
	if keyErr := verifyStagingSigningKey(ctx, cfg, store, manifest, log); keyErr != nil {
		return keyErr
	}
	if preErr := checkProvisioningPreconditions(cfg, manifest); preErr != nil {
		return preErr
	}

	localRooms, err := store.ReadLocalRooms()
	if err != nil {
		return fmt.Errorf("read local_rooms.json: %w", err)
	}

	accountsByID, orderedAccounts, err := restoreAllAccounts(ctx, cfg, store, manifest, log)
	if err != nil {
		return err
	}

	createdCount, skippedCount, err := rebuildLocalRooms(ctx, cfg, store, manifest, localRooms.Rooms, accountsByID, log)
	if err != nil {
		return err
	}

	if err := restoreTagsAndDirectMaps(ctx, orderedAccounts, manifest.LocalRoomMap); err != nil {
		return err
	}

	if err := restoreLocalTrustGraph(ctx, store, orderedAccounts); err != nil {
		return err
	}

	manifest.Phase = dump.PhaseImportedLocal
	if err := writeManifest(store, manifest); err != nil {
		return fmt.Errorf("write final manifest state: %w", err)
	}

	log.Info().
		Int("accounts", len(orderedAccounts)).
		Int("created_local_rooms", createdCount).
		Int("skipped_existing_rooms", skippedCount).
		Msg("Tuwunel local import completed")

	return nil
}

func loadImportManifest(store *dump.Store) (*dump.ManifestState, error) {
	manifest, err := store.ReadManifest()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissingManifest
		}
		return nil, fmt.Errorf("read manifest_state.json: %w", err)
	}
	if manifest.LocalRoomMap == nil {
		manifest.LocalRoomMap = make(map[string]string)
	}
	if manifest.ProvisionedUsers == nil {
		manifest.ProvisionedUsers = make(map[string]bool)
	}
	return manifest, nil
}

func checkProvisioningPreconditions(cfg *config.Config, manifest *dump.ManifestState) error {
	for i := range cfg.Accounts {
		acc := &cfg.Accounts[i]
		if !acc.ExistsOnTuwunel && !manifest.ProvisionedUsers[acc.UserID] && cfg.TuwunelSharedSecret == "" {
			return fmt.Errorf("account %s: %w", acc.UserID, matrix.ErrEmptySharedSecret)
		}
	}
	return nil
}

func verifyStagingSigningKey(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	manifest *dump.ManifestState,
	log *zerolog.Logger,
) error {
	if err := store.ValidateSigningKeyTOML(); err != nil {
		return fmt.Errorf("verify server signing key drop-in: %w", err)
	}
	probeRes, err := signingkey.VerifyServerKeyState(ctx, nil, cfg.TuwunelURL, cfg.ServerName, manifest, false)
	if err != nil {
		return fmt.Errorf("verify server signing key state: %w", err)
	}
	if probeRes == signingkey.KeyProbeFederationDisabled {
		log.Debug().Str("key_id", manifest.ServerSigningKeyID).Msg("Tuwunel federation disabled on staging; skipping live /_matrix/key/v2/server cryptographic probe")
		return nil
	}
	log.Debug().Str("key_id", manifest.ServerSigningKeyID).Msg("Verified live Tuwunel /_matrix/key/v2/server key matches prepared Synapse key")
	return nil
}

func restoreAllAccounts(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	manifest *dump.ManifestState,
	log *zerolog.Logger,
) (map[string]*importedAccount, []*importedAccount, error) {
	byID := make(map[string]*importedAccount, len(cfg.Accounts))
	ordered := make([]*importedAccount, 0, len(cfg.Accounts))

	for i := range cfg.Accounts {
		acc := &cfg.Accounts[i]
		restored, err := restoreSingleAccount(ctx, cfg, store, manifest, acc, log)
		if err != nil {
			return nil, nil, fmt.Errorf("import account %s: %w", acc.UserID, err)
		}
		byID[acc.UserID] = restored
		ordered = append(ordered, restored)
	}
	return byID, ordered, nil
}

func restoreSingleAccount(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	manifest *dump.ManifestState,
	acc *config.AccountConfig,
	log *zerolog.Logger,
) (*importedAccount, error) {
	cli, err := authenticateTuwunelAccount(ctx, cfg, store, manifest, acc, log)
	if err != nil {
		return nil, err
	}

	mach, stateStore, err := newOlmMachine(ctx, cli, log)
	if err != nil {
		return nil, fmt.Errorf("init olm machine: %w", err)
	}
	cli.StateStore = stateStore

	identity, err := store.ReadIdentity(acc.UserID)
	if err != nil {
		return nil, fmt.Errorf("read identity.json: %w", err)
	}
	if cryptoErr := restoreCryptoIdentity(ctx, cli, mach, acc, identity); cryptoErr != nil {
		return nil, cryptoErr
	}

	profile, err := store.ReadProfile(acc.UserID)
	if err != nil {
		return nil, fmt.Errorf("read profile.json: %w", err)
	}
	if profErr := restoreProfile(ctx, cli, store, profile); profErr != nil {
		return nil, profErr
	}

	backupKey, backupVersion, err := restoreKeyBackup(ctx, cli, mach, store, acc.UserID, identity, log)
	if err != nil {
		return nil, err
	}

	return &importedAccount{
		cli:           cli,
		mach:          mach,
		stateStore:    stateStore,
		identity:      identity,
		profile:       profile,
		backupKey:     backupKey,
		userID:        acc.UserID,
		backupVersion: backupVersion,
	}, nil
}

func authenticateTuwunelAccount(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	manifest *dump.ManifestState,
	acc *config.AccountConfig,
	log *zerolog.Logger,
) (*mautrix.Client, error) {
	if err := cleanupPriorSession(ctx, cfg.TuwunelURL, store, acc.UserID, log); err != nil {
		return nil, err
	}

	if !acc.ExistsOnTuwunel && !manifest.ProvisionedUsers[acc.UserID] {
		regResp, err := matrix.RegisterSharedSecret(ctx, cfg.TuwunelURL, cfg.TuwunelSharedSecret, acc.Localpart(), acc.TuwunelPassword, acc.Admin)
		if err != nil {
			return nil, fmt.Errorf("register user on Tuwunel: %w", err)
		}
		manifest.ProvisionedUsers[acc.UserID] = true
		if writeErr := writeManifest(store, manifest); writeErr != nil {
			return nil, fmt.Errorf("persist provisioned user state: %w", writeErr)
		}
		cli, _, err := matrix.ConnectWithToken(ctx, cfg.TuwunelURL, acc.UserID, regResp.AccessToken, log)
		if err != nil {
			return nil, fmt.Errorf("verify registered session: %w", err)
		}
		if err := saveSession(store, cfg.TuwunelURL, acc.UserID, cli); err != nil {
			return nil, err
		}
		return cli, nil
	}

	cli, _, err := matrix.LoginPassword(ctx, cfg.TuwunelURL, acc.UserID, acc.TuwunelPassword, matrix.DefaultDeviceDisplayName, log)
	if err != nil {
		return nil, fmt.Errorf("login on Tuwunel: %w", err)
	}
	if err := saveSession(store, cfg.TuwunelURL, acc.UserID, cli); err != nil {
		return nil, err
	}
	return cli, nil
}

func cleanupPriorSession(ctx context.Context, tuwunelURL string, store *dump.Store, userID string, log *zerolog.Logger) error {
	sess, err := store.ReadSession(userID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read previous session.json: %w", err)
	}
	if sess.AccessToken != "" {
		oldCli, _, connErr := matrix.ConnectWithToken(ctx, tuwunelURL, userID, sess.AccessToken, log)
		if connErr == nil {
			if _, logoutErr := oldCli.Logout(ctx); logoutErr != nil && !isAuthOrNotFoundErr(logoutErr) {
				log.Warn().Err(logoutErr).Str("user_id", userID).Msg("Failed to log out previous migration device on Tuwunel")
			}
		}
	}
	if err := removeSession(store, userID); err != nil {
		return fmt.Errorf("remove stale session.json: %w", err)
	}
	return nil
}

func saveSession(store *dump.Store, homeserverURL, userID string, cli *mautrix.Client) error {
	err := writeSession(store, userID, &dump.SessionData{
		UserID:        userID,
		HomeserverURL: homeserverURL,
		AccessToken:   cli.AccessToken,
		DeviceID:      cli.DeviceID.String(),
	})
	if err != nil {
		return fmt.Errorf("write session.json: %w", err)
	}
	return nil
}

func restoreCryptoIdentity(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	acc *config.AccountConfig,
	identity *dump.IdentityData,
) error {
	if err := mach.ShareKeys(ctx, 0); err != nil {
		return fmt.Errorf("upload device keys: %w", err)
	}

	seeds := crypto.CrossSigningSeeds{
		MasterKey:      slices.Clone(identity.MasterSeed),
		SelfSigningKey: slices.Clone(identity.SelfSigningSeed),
		UserSigningKey: slices.Clone(identity.UserSigningSeed),
	}
	if err := mach.ImportCrossSigningKeys(seeds); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidLocalSeed, err)
	}

	uid := id.UserID(acc.UserID)
	if err := mach.PublishCrossSigningKeys(ctx, mach.CrossSigningKeys, matrix.PasswordUIACallback(uid, acc.TuwunelPassword)); err != nil {
		return fmt.Errorf("publish cross-signing keys: %w", err)
	}
	if err := mach.SignOwnMasterKey(ctx); err != nil {
		return fmt.Errorf("sign own master key: %w", err)
	}
	if err := mach.SignOwnDevice(ctx, mach.OwnIdentity()); err != nil {
		return fmt.Errorf("sign own device key: %w", err)
	}

	keys := make([]string, 0, len(identity.RawSSSSAccountData))
	for evtType := range identity.RawSSSSAccountData {
		keys = append(keys, evtType)
	}
	sort.Strings(keys)

	for _, evtType := range keys {
		raw := identity.RawSSSSAccountData[evtType]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		if err := cli.SetAccountData(ctx, evtType, raw); err != nil {
			return fmt.Errorf("upload SSSS account data %s: %w", evtType, err)
		}
	}
	return nil
}

func restoreProfile(ctx context.Context, cli *mautrix.Client, store *dump.Store, profile *dump.ProfileData) error {
	if profile.DisplayName != "" {
		if err := cli.SetDisplayName(ctx, profile.DisplayName); err != nil {
			return fmt.Errorf("set displayname: %w", err)
		}
	}
	if profile.Avatar != nil && profile.Avatar.SHA256 != "" {
		raw, err := store.ReadMedia(profile.Avatar.SHA256)
		if err != nil {
			return fmt.Errorf("read user avatar media %s: %w", profile.Avatar.SHA256, err)
		}
		contentType := profile.Avatar.ContentType
		if contentType == "" {
			contentType = roomAvatarDefaultMime
		}
		upResp, err := cli.UploadBytesWithName(ctx, raw, contentType, profile.Avatar.FileName)
		if err != nil {
			return fmt.Errorf("upload user avatar: %w", err)
		}
		if err := cli.SetAvatarURL(ctx, upResp.ContentURI); err != nil {
			return fmt.Errorf("set avatar URL: %w", err)
		}
	}
	if len(profile.IgnoredUsers) > 0 {
		if err := cli.SetAccountData(ctx, event.AccountDataIgnoredUserList.Type, profile.IgnoredUsers); err != nil {
			return fmt.Errorf("restore ignored users list: %w", err)
		}
	}
	return nil
}

func restoreKeyBackup(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	store *dump.Store,
	userID string,
	identity *dump.IdentityData,
	log *zerolog.Logger,
) (*backup.MegolmBackupKey, string, error) {
	roomKeys, err := store.ReadRoomKeys(userID)
	if err != nil {
		return nil, "", fmt.Errorf("read room_keys.json: %w", err)
	}
	if identity.KeyBackupVersion == "" || len(identity.MegolmBackupKey) == 0 {
		log.Warn().Str("user_id", userID).Msg("Online key backup metadata is empty in export; skipping room_keys restore")
		return nil, "", nil
	}

	megolmKey, err := backup.MegolmBackupKeyFromBytes(identity.MegolmBackupKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse megolm backup private key: %w", err)
	}

	version, err := ensureTuwunelBackupVersion(ctx, cli, mach, userID, identity)
	if err != nil {
		return nil, "", err
	}
	if len(roomKeys.Rooms) > 0 {
		if err := uploadBackupSessionsBatched(ctx, cli, version, roomKeys.Rooms); err != nil {
			return nil, "", err
		}
	}
	return megolmKey, string(version), nil
}

func ensureTuwunelBackupVersion(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	userID string,
	identity *dump.IdentityData,
) (id.KeyBackupVersion, error) {
	expectedPub := id.Ed25519(identity.MegolmBackupPublicKey)
	latest, err := cli.GetKeyBackupLatestVersion(ctx)
	if err == nil && latest != nil && latest.Algorithm == id.KeyBackupAlgorithmMegolmBackupV1 && latest.AuthData.PublicKey == expectedPub {
		return latest.Version, nil
	}
	if err != nil && !isNotFoundErr(err) {
		return "", fmt.Errorf("check existing key backup version on Tuwunel: %w", err)
	}

	authData := backup.MegolmAuthData{
		PublicKey: expectedPub,
	}
	sig, err := mach.CrossSigningKeys.MasterKey.SignJSON(&authData)
	if err != nil {
		return "", fmt.Errorf("sign key backup auth_data: %w", err)
	}
	authData.Signatures = signatures.NewSingleSignature(id.UserID(userID), id.KeyAlgorithmEd25519, identity.MasterPublicKey, sig)

	created, err := cli.CreateKeyBackupVersion(ctx, &mautrix.ReqRoomKeysVersionCreate[backup.MegolmAuthData]{
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  authData,
	})
	if err != nil {
		return "", fmt.Errorf("create key backup version on Tuwunel: %w", err)
	}
	return created.Version, nil
}

func uploadBackupSessionsBatched(
	ctx context.Context,
	cli *mautrix.Client,
	version id.KeyBackupVersion,
	rooms map[string]dump.RoomKeyBackupRoom,
) error {
	roomIDs := make([]string, 0, len(rooms))
	for roomID, roomData := range rooms {
		if len(roomData.Sessions) > 0 {
			roomIDs = append(roomIDs, roomID)
		}
	}
	sort.Strings(roomIDs)

	batch := make(map[id.RoomID]mautrix.ReqRoomKeyBackup)
	count := 0

	flush := func() error {
		if count == 0 {
			return nil
		}
		if _, err := cli.PutKeysInBackup(ctx, version, &mautrix.ReqKeyBackup{Rooms: batch}); err != nil {
			return fmt.Errorf("upload room_keys batch: %w", err)
		}
		batch = make(map[id.RoomID]mautrix.ReqRoomKeyBackup)
		count = 0
		return nil
	}

	for _, roomIDStr := range roomIDs {
		sessions := rooms[roomIDStr].Sessions
		sessIDs := make([]string, 0, len(sessions))
		for sessID := range sessions {
			sessIDs = append(sessIDs, sessID)
		}
		sort.Strings(sessIDs)

		roomID := id.RoomID(roomIDStr)
		for _, sessIDStr := range sessIDs {
			entry := sessions[sessIDStr]
			roomBucket, ok := batch[roomID]
			if !ok {
				roomBucket = mautrix.ReqRoomKeyBackup{
					Sessions: make(map[id.SessionID]mautrix.ReqKeyBackupData),
				}
			}
			roomBucket.Sessions[id.SessionID(sessIDStr)] = mautrix.ReqKeyBackupData{
				FirstMessageIndex: entry.FirstMessageIndex,
				ForwardedCount:    entry.ForwardedCount,
				IsVerified:        entry.IsVerified,
				SessionData:       entry.SessionData,
			}
			batch[roomID] = roomBucket
			count++
			if count >= backupUploadBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}

	return flush()
}

func rebuildLocalRooms(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	manifest *dump.ManifestState,
	rooms []dump.LocalRoom,
	accountsByID map[string]*importedAccount,
	log *zerolog.Logger,
) (createdCount, skippedCount int, retErr error) {
	newlyCreated := make(map[string]bool)

	for _, isSpacePass := range []bool{false, true} {
		for i := range rooms {
			room := &rooms[i]
			if (room.RoomType == spaceRoomType) != isSpacePass {
				continue
			}
			if existingID := manifest.LocalRoomMap[room.OldRoomID]; existingID != "" {
				skippedCount++
				continue
			}
			newRoomID, err := createAndPopulateLocalRoom(ctx, cfg, store, room, accountsByID, log)
			if err != nil {
				return createdCount, skippedCount, fmt.Errorf("recreate local room %s: %w", room.OldRoomID, err)
			}
			manifest.LocalRoomMap[room.OldRoomID] = newRoomID.String()
			newlyCreated[room.OldRoomID] = true
			if err := writeManifest(store, manifest); err != nil {
				return createdCount, skippedCount, fmt.Errorf("persist local room mapping for %s: %w", room.OldRoomID, err)
			}
			createdCount++
		}
	}

	if err := syncCreatedSpaceChildren(ctx, cfg.ServerName, rooms, manifest.LocalRoomMap, newlyCreated, accountsByID); err != nil {
		return createdCount, skippedCount, err
	}
	return createdCount, skippedCount, nil
}

func createAndPopulateLocalRoom(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	room *dump.LocalRoom,
	accountsByID map[string]*importedAccount,
	log *zerolog.Logger,
) (id.RoomID, error) {
	creator, ok := accountsByID[room.ChosenCreator]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrMissingCreator, room.ChosenCreator)
	}

	req, err := buildCreateRoomRequest(ctx, cfg, store, creator.cli, room)
	if err != nil {
		return "", err
	}
	resp, err := creator.cli.CreateRoom(ctx, req)
	if err != nil {
		return "", fmt.Errorf("createRoom request: %w", err)
	}

	if err := joinInvitedMembers(ctx, resp.RoomID, room, accountsByID); err != nil {
		return "", err
	}

	if cfg.ReplaySingleUserNotes && room.Category == dump.RoomCategoryNotes && len(room.Notes) > 0 {
		if err := replayRoomNotes(ctx, store, creator, resp.RoomID, room, log); err != nil {
			return "", fmt.Errorf("replay notes into %s: %w", resp.RoomID, err)
		}
	}
	return resp.RoomID, nil
}

func buildCreateRoomRequest(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	creatorCli *mautrix.Client,
	room *dump.LocalRoom,
) (*mautrix.ReqCreateRoom, error) {
	roomVersion := cfg.LocalRoomVersion
	if roomVersion == "" {
		roomVersion = roomVersionTwelve
	}

	initialState, err := buildInitialState(ctx, store, creatorCli, room)
	if err != nil {
		return nil, err
	}

	invites := make([]id.UserID, 0, len(room.JoinedMembers))
	for _, member := range room.JoinedMembers {
		if member != room.ChosenCreator {
			invites = append(invites, id.UserID(member))
		}
	}

	creationContent := buildCreationContent(room, roomVersion)
	powerOverride := buildPowerLevelsOverride(room.PowerLevels)

	return &mautrix.ReqCreateRoom{
		Visibility:         defaultRoomVisibility,
		Name:               room.Name,
		Topic:              room.Topic,
		Invite:             invites,
		CreationContent:    creationContent,
		InitialState:       initialState,
		IsDirect:           room.IsDirect,
		RoomVersion:        id.RoomVersion(roomVersion),
		PowerLevelOverride: powerOverride,
	}, nil
}

func buildCreationContent(room *dump.LocalRoom, roomVersion string) map[string]any {
	content := make(map[string]any)
	if room.RoomType != "" {
		content["type"] = room.RoomType
	}
	if roomVersion == roomVersionTwelve && len(room.AdditionalCreators) > 0 {
		content["additional_creators"] = room.AdditionalCreators
	}
	if len(content) == 0 {
		return nil
	}
	return content
}

func buildPowerLevelsOverride(pl *dump.PowerLevelsConfig) *event.PowerLevelsEventContent {
	if pl == nil {
		return nil
	}
	users := make(map[id.UserID]int, len(pl.Users))
	for uid, level := range pl.Users {
		users[id.UserID(uid)] = level
	}
	stateDefault := pl.StateDefault
	invite := pl.Invite
	kick := pl.Kick
	ban := pl.Ban
	redact := pl.Redact

	var notifications *event.NotificationPowerLevels
	if level, ok := pl.Notifications["room"]; ok {
		roomNotif := level
		notifications = &event.NotificationPowerLevels{RoomPtr: &roomNotif}
	}

	return &event.PowerLevelsEventContent{
		Users:           users,
		UsersDefault:    pl.UsersDefault,
		Events:          maps.Clone(pl.Events),
		EventsDefault:   pl.EventsDefault,
		Notifications:   notifications,
		StateDefaultPtr: &stateDefault,
		InvitePtr:       &invite,
		KickPtr:         &kick,
		BanPtr:          &ban,
		RedactPtr:       &redact,
	}
}

func buildInitialState(
	ctx context.Context,
	store *dump.Store,
	creatorCli *mautrix.Client,
	room *dump.LocalRoom,
) ([]*event.Event, error) {
	var events []*event.Event

	if room.Encryption != nil && room.Encryption.Algorithm != "" {
		events = append(events, makeStateEvent(event.StateEncryption, &event.EncryptionEventContent{
			Algorithm:              id.Algorithm(room.Encryption.Algorithm),
			RotationPeriodMillis:   room.Encryption.RotationPeriodMillis,
			RotationPeriodMessages: room.Encryption.RotationPeriodMsgs,
		}))
	}
	if room.Retention != nil && (room.Retention.MaxLifetime != nil || room.Retention.MinLifetime != nil) {
		events = append(events, makeStateEvent(stateRoomRetention, room.Retention))
	}
	if room.HistoryVisibility != "" {
		events = append(events, makeStateEvent(event.StateHistoryVisibility, &event.HistoryVisibilityEventContent{
			HistoryVisibility: event.HistoryVisibility(room.HistoryVisibility),
		}))
	}
	if room.JoinRule != "" {
		events = append(events, makeStateEvent(event.StateJoinRules, &event.JoinRulesEventContent{
			JoinRule: event.JoinRule(room.JoinRule),
		}))
	}
	if room.GuestAccess != "" {
		events = append(events, makeStateEvent(event.StateGuestAccess, &event.GuestAccessEventContent{
			GuestAccess: event.GuestAccess(room.GuestAccess),
		}))
	}
	if room.Avatar != nil && room.Avatar.SHA256 != "" {
		raw, err := store.ReadMedia(room.Avatar.SHA256)
		if err != nil {
			return nil, fmt.Errorf("read room avatar media %s: %w", room.Avatar.SHA256, err)
		}
		ct := room.Avatar.ContentType
		if ct == "" {
			ct = roomAvatarDefaultMime
		}
		upResp, err := creatorCli.UploadBytesWithName(ctx, raw, ct, room.Avatar.FileName)
		if err != nil {
			return nil, fmt.Errorf("upload room avatar: %w", err)
		}
		events = append(events, makeStateEvent(event.StateRoomAvatar, &event.RoomAvatarEventContent{
			URL:  id.ContentURIString(upResp.ContentURI.String()),
			Info: &event.FileInfo{MimeType: ct, Size: int(room.Avatar.Size)},
		}))
	}
	return events, nil
}

func makeStateEvent(evtType event.Type, parsed any) *event.Event {
	emptyKey := ""
	return &event.Event{
		Type:     evtType,
		StateKey: &emptyKey,
		Content:  event.Content{Parsed: parsed},
	}
}

func joinInvitedMembers(
	ctx context.Context,
	newRoomID id.RoomID,
	room *dump.LocalRoom,
	accountsByID map[string]*importedAccount,
) error {
	for _, memberID := range room.JoinedMembers {
		if memberID == room.ChosenCreator {
			continue
		}
		memberAcc, ok := accountsByID[memberID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingMember, memberID)
		}
		if _, err := joinRoomByID(ctx, memberAcc.cli, newRoomID); err != nil {
			return fmt.Errorf("auto-join %s into %s: %w", memberID, newRoomID, err)
		}
	}
	return nil
}

func syncCreatedSpaceChildren(
	ctx context.Context,
	serverName string,
	rooms []dump.LocalRoom,
	localRoomMap map[string]string,
	newlyCreated map[string]bool,
	accountsByID map[string]*importedAccount,
) error {
	for i := range rooms {
		room := &rooms[i]
		if room.RoomType != spaceRoomType || len(room.SpaceChildren) == 0 {
			continue
		}
		if !shouldSyncSpace(room, newlyCreated) {
			continue
		}
		spaceIDStr := localRoomMap[room.OldRoomID]
		if spaceIDStr == "" {
			continue
		}
		creator, ok := accountsByID[room.ChosenCreator]
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingCreator, room.ChosenCreator)
		}
		spaceID := id.RoomID(spaceIDStr)
		for _, child := range room.SpaceChildren {
			targetChildID := child.ChildRoomID
			via := slices.Clone(child.Via)
			if remapped, isLocal := localRoomMap[child.ChildRoomID]; isLocal {
				targetChildID = remapped
				if len(via) == 0 {
					via = []string{serverName}
				}
			}
			content := &event.SpaceChildEventContent{
				Via:       via,
				Order:     child.Order,
				Suggested: child.Suggested,
			}
			if _, err := creator.cli.SendStateEvent(ctx, spaceID, event.StateSpaceChild, targetChildID, content); err != nil {
				return fmt.Errorf("set space child %s on %s: %w", targetChildID, spaceID, err)
			}
		}
	}
	return nil
}

func shouldSyncSpace(space *dump.LocalRoom, newlyCreated map[string]bool) bool {
	if newlyCreated[space.OldRoomID] {
		return true
	}
	for _, child := range space.SpaceChildren {
		if newlyCreated[child.ChildRoomID] {
			return true
		}
	}
	return false
}

func restoreTagsAndDirectMaps(
	ctx context.Context,
	orderedAccounts []*importedAccount,
	localRoomMap map[string]string,
) error {
	for _, acc := range orderedAccounts {
		if err := applyLocalRoomTags(ctx, acc.cli, acc.profile.RoomTags, localRoomMap); err != nil {
			return fmt.Errorf("restore tags for %s: %w", acc.userID, err)
		}
		if len(acc.profile.Direct) > 0 {
			remapped := classifier.RemapDirectMap(acc.profile.Direct, localRoomMap)
			if len(remapped) > 0 {
				if err := acc.cli.SetAccountData(ctx, event.AccountDataDirectChats.Type, remapped); err != nil {
					return fmt.Errorf("upload m.direct for %s: %w", acc.userID, err)
				}
			}
		}
	}
	return nil
}

func applyLocalRoomTags(
	ctx context.Context,
	cli *mautrix.Client,
	roomTags map[string]map[string]dump.RoomTagEntry,
	localRoomMap map[string]string,
) error {
	oldRoomIDs := make([]string, 0, len(roomTags))
	for oldRoomID := range roomTags {
		oldRoomIDs = append(oldRoomIDs, oldRoomID)
	}
	sort.Strings(oldRoomIDs)

	for _, oldRoomID := range oldRoomIDs {
		newRoomID, isLocal := localRoomMap[oldRoomID]
		if !isLocal || newRoomID == "" {
			continue
		}
		tags := roomTags[oldRoomID]
		tagNames := make([]string, 0, len(tags))
		for name := range tags {
			tagNames = append(tagNames, name)
		}
		sort.Strings(tagNames)

		for _, name := range tagNames {
			var meta event.TagMetadata
			entry := tags[name]
			if entry.Order != nil {
				meta.Order = json.Number(strconv.FormatFloat(*entry.Order, 'f', -1, 64))
			}
			if err := cli.AddTagWithCustomData(ctx, id.RoomID(newRoomID), event.RoomTag(name), &meta); err != nil {
				return fmt.Errorf("apply tag %s on %s: %w", name, newRoomID, err)
			}
		}
	}
	return nil
}

func restoreLocalTrustGraph(ctx context.Context, store *dump.Store, orderedAccounts []*importedAccount) error {
	for _, acc := range orderedAccounts {
		trustGraph, err := store.ReadTrustGraph(acc.userID)
		if err != nil {
			return fmt.Errorf("read trust_graph.json for %s: %w", acc.userID, err)
		}
		if err := signLocalContacts(ctx, acc, trustGraph.Contacts); err != nil {
			return fmt.Errorf("restore local trust signatures for %s: %w", acc.userID, err)
		}
	}
	return nil
}

func signLocalContacts(ctx context.Context, acc *importedAccount, contacts []dump.TrustedContact) error {
	reqDevices := make(mautrix.DeviceKeysRequest)
	var localTargets []dump.TrustedContact
	for _, contact := range contacts {
		if !contact.Local || contact.UserID == acc.userID {
			continue
		}
		localTargets = append(localTargets, contact)
		reqDevices[id.UserID(contact.UserID)] = []id.DeviceID{}
	}
	if len(localTargets) == 0 {
		return nil
	}

	resp, err := acc.cli.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		Timeout:    keysQueryTimeoutMs,
		DeviceKeys: reqDevices,
	})
	if err != nil {
		return fmt.Errorf("query local master keys: %w", err)
	}

	ownerID := id.UserID(acc.userID)
	userSigningPub := acc.mach.CrossSigningKeys.UserSigningKey.PublicKey()

	for _, contact := range localTargets {
		targetID := id.UserID(contact.UserID)
		mk, exists := resp.MasterKeys[targetID]
		serverMaster := mk.FirstKey()
		if !exists || serverMaster == "" || serverMaster.String() != contact.MasterKey {
			return fmt.Errorf("%w for %s: server=%q expected=%q", ErrMasterKeyMismatch, contact.UserID, serverMaster, contact.MasterKey)
		}
		alreadySigned, sigErr := signatures.VerifySignatureJSON(&mk, ownerID, userSigningPub.String(), userSigningPub)
		if sigErr == nil && alreadySigned {
			continue
		}
		if err := acc.mach.SignUser(ctx, targetID, serverMaster); err != nil {
			return fmt.Errorf("sign user %s: %w", contact.UserID, err)
		}
	}
	return nil
}

func isNotFoundErr(err error) bool {
	return matrix.IsHTTPStatus(err, http.StatusNotFound) || matrix.IsMatrixErrCode(err, mautrix.MNotFound.ErrCode)
}

func isAuthOrNotFoundErr(err error) bool {
	return isNotFoundErr(err) || matrix.IsHTTPStatus(err, http.StatusUnauthorized) || matrix.IsMatrixErrCode(err, mautrix.MUnknownToken.ErrCode)
}
