// Package exporter extracts and cryptographically validates Synapse accounts, rooms, media, and trust signatures.
package exporter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/classifier"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

const keysQueryTimeoutMs = 5000

// Sentinel errors returned when Synapse export or pre-flight cryptographic verification fails.
var (
	ErrNilConfig            = errors.New("config must not be nil")
	ErrNilStore             = errors.New("dump store must not be nil")
	ErrCrossSigningMismatch = errors.New("decrypted cross-signing keys do not match server public keys")
	ErrBackupKeyMismatch    = errors.New("decrypted megolm backup key does not match server backup version")
	ErrBackupCorrupted      = errors.New("megolm key backup session test decryption failed")
	ErrMissingBackupKey     = errors.New("server key backup exists but m.megolm_backup.v1 is missing from SSSS")
	ErrUnsupportedBackupAlg = errors.New("unsupported megolm key backup algorithm")
)

func defaultNowUTC() time.Time {
	return time.Now().UTC()
}

func defaultJSONMarshal(v any) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON payload: %w", err)
	}
	return encoded, nil
}

var (
	nowUTC        = defaultNowUTC
	jsonMarshal   = defaultJSONMarshal
	newOlmMachine = matrix.NewOlmMachine
)

type exportedAccountState struct {
	identity   *dump.IdentityData
	roomKeys   *dump.RoomKeysData
	profile    *dump.ProfileData
	trustGraph *dump.TrustGraphData
	userID     string
}

type extractedBackup struct {
	megolmKey      *backup.MegolmBackupKey
	roomKeys       *dump.RoomKeysData
	sessionsByRoom map[id.RoomID]map[id.SessionID]backup.EncryptedSessionData[backup.MegolmSessionData]
	publicKey      string
	version        string
	rawKeyBytes    []byte
	hasSSSSKey     bool
}

type collectedRooms struct {
	roomTags      map[string]map[string]dump.RoomTagEntry
	joinedRoomIDs []id.RoomID
	extCandidates []string
}

// Run exports and verifies all configured Synapse accounts into the hardened migration dump store.
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
	if err := cfg.ValidateForMode(config.ModeExport); err != nil {
		return fmt.Errorf("validate export config: %w", err)
	}

	manifest, err := loadOrInitManifest(cfg, store)
	if err != nil {
		return err
	}

	allowlisted := cfg.AllowlistedUserSet()
	directRoomSet := make(map[string]struct{})
	observationsByRoom := make(map[string]*classifier.RoomObservation)
	notesByRoom := make(map[string][]dump.NoteEntry)
	exportedAccounts := make([]*exportedAccountState, 0, len(cfg.Accounts))

	for i := range cfg.Accounts {
		acc := &cfg.Accounts[i]
		accState, accErr := exportSingleAccount(
			ctx,
			cfg,
			store,
			acc,
			allowlisted,
			observationsByRoom,
			directRoomSet,
			notesByRoom,
			log,
		)
		if accErr != nil {
			return fmt.Errorf("export account %s: %w", acc.UserID, accErr)
		}
		exportedAccounts = append(exportedAccounts, accState)
	}

	observations := make([]classifier.RoomObservation, 0, len(observationsByRoom))
	for _, obs := range observationsByRoom {
		observations = append(observations, *obs)
	}

	corpus := classifier.ClassifyCorpus(observations, classifier.ClassifyOptions{
		AllowlistedUsers: allowlisted,
		DirectRoomIDs:    directRoomSet,
		ServerName:       cfg.ServerName,
		LocalRoomVersion: cfg.LocalRoomVersion,
	})

	if persistErr := persistExportOutputs(store, cfg, manifest, &corpus, exportedAccounts, notesByRoom, allowlisted); persistErr != nil {
		return persistErr
	}

	logExcludedRooms(corpus.ExcludedRooms, log)
	logPartialLocalRooms(corpus.PartialLocalRooms, log)

	log.Info().
		Int("accounts", len(exportedAccounts)).
		Int("local_rooms", len(corpus.LocalRooms)).
		Int("partial_local_rooms", len(corpus.PartialLocalRooms)).
		Int("federated_rooms", len(corpus.FederatedRooms)).
		Int("excluded_rooms", len(corpus.BridgeOrOrphanRooms)).
		Msg("Synapse export and cryptographic verification completed")

	return nil
}

func logExcludedRooms(excluded []classifier.ExcludedRoom, log *zerolog.Logger) {
	for i := range excluded {
		room := &excluded[i]
		evt := log.Warn().
			Str("room_id", room.RoomID).
			Str("reason", room.Reason)
		if room.RoomName != "" {
			evt = evt.Str("room_name", room.RoomName)
		}
		if len(room.BridgeUsers) > 0 {
			evt = evt.Strs("blocking_users", room.BridgeUsers)
		}
		if len(room.ExcludedJoinedLocalUsers) > 0 {
			evt = evt.Strs("excluded_joined_local_users", room.ExcludedJoinedLocalUsers)
		}
		if len(room.DepartedLocalUsers) > 0 {
			evt = evt.Strs("departed_local_users", room.DepartedLocalUsers)
		}
		if len(room.DepartedExternalUsers) > 0 {
			evt = evt.Strs("departed_external_users", room.DepartedExternalUsers)
		}
		if len(room.JoinedLocalUsers) > 0 {
			evt = evt.Strs("joined_local_users", room.JoinedLocalUsers)
		}
		evt.Msg("Excluded Synapse room from migration")
	}
}

func logPartialLocalRooms(partial []classifier.PartialLocalRoom, log *zerolog.Logger) {
	for i := range partial {
		room := &partial[i]
		evt := log.Warn().
			Str("room_id", room.RoomID)
		if room.RoomName != "" {
			evt = evt.Str("room_name", room.RoomName)
		}
		if len(room.JoinedLocalUsers) > 0 {
			evt = evt.Strs("joined_local_users", room.JoinedLocalUsers)
		}
		if len(room.ExcludedJoinedLocalUsers) > 0 {
			evt = evt.Strs("excluded_joined_local_users", room.ExcludedJoinedLocalUsers)
		}
		if len(room.DepartedLocalUsers) > 0 {
			evt = evt.Strs("departed_local_users", room.DepartedLocalUsers)
		}
		if len(room.DepartedExternalUsers) > 0 {
			evt = evt.Strs("departed_external_users", room.DepartedExternalUsers)
		}
		evt.Msg("Migrated local room excluding non-allowlisted or departed participants")
	}
}

func loadOrInitManifest(cfg *config.Config, store *dump.Store) (*dump.ManifestState, error) {
	existing, err := store.ReadManifest()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read existing manifest state: %w", err)
		}
		return &dump.ManifestState{
			LocalRoomMap:     make(map[string]string),
			ProvisionedUsers: make(map[string]bool),
			ServerName:       cfg.ServerName,
			LocalRoomVersion: cfg.LocalRoomVersion,
		}, nil
	}
	if existing.LocalRoomMap == nil {
		existing.LocalRoomMap = make(map[string]string)
	}
	if existing.ProvisionedUsers == nil {
		existing.ProvisionedUsers = make(map[string]bool)
	}
	return existing, nil
}

func exportSingleAccount(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	acc *config.AccountConfig,
	allowlisted map[string]struct{},
	observationsByRoom map[string]*classifier.RoomObservation,
	directRoomSet map[string]struct{},
	notesByRoom map[string][]dump.NoteEntry,
	log *zerolog.Logger,
) (*exportedAccountState, error) {
	cli, ownsDevice, authErr := authenticateSynapse(ctx, cfg.SynapseURL, acc, log)
	if authErr != nil {
		return nil, authErr
	}
	defer func() {
		if ownsDevice {
			logoutSynapseSession(ctx, cli, acc.UserID, log)
		}
	}()

	mach, stateStore, machErr := newOlmMachine(ctx, cli, log)
	if machErr != nil {
		return nil, fmt.Errorf("init olm machine: %w", machErr)
	}

	identity, backupData, pubKeys, idErr := verifyAndExportIdentity(ctx, cli, mach, acc, log)
	if idErr != nil {
		return nil, idErr
	}

	profile, profErr := exportProfileData(ctx, cli, store, acc.UserID, directRoomSet, log)
	if profErr != nil {
		return nil, profErr
	}

	collected, roomsErr := exportJoinedRooms(ctx, cli, store, cfg.ServerName, acc.UserID, allowlisted, observationsByRoom, log)
	if roomsErr != nil {
		return nil, roomsErr
	}
	if len(collected.roomTags) > 0 {
		profile.RoomTags = collected.roomTags
	}

	if cfg.ReplaySingleUserNotes {
		if notesErr := exportAccountSingleUserNotes(
			ctx,
			cli,
			mach,
			stateStore,
			store,
			cfg,
			acc,
			allowlisted,
			collected,
			observationsByRoom,
			backupData,
			notesByRoom,
			log,
		); notesErr != nil {
			return nil, notesErr
		}
	}

	trustGraph, trustErr := exportTrustGraph(ctx, cli, cfg, acc, pubKeys.UserSigningKey, collected.extCandidates, profile.Direct, log)
	if trustErr != nil {
		return nil, trustErr
	}

	return &exportedAccountState{
		userID:     acc.UserID,
		identity:   identity,
		roomKeys:   backupData.roomKeys,
		profile:    profile,
		trustGraph: trustGraph,
	}, nil
}

func authenticateSynapse(ctx context.Context, synapseURL string, acc *config.AccountConfig, log *zerolog.Logger) (*mautrix.Client, bool, error) {
	if acc.SynapseAccessToken != "" {
		cli, _, err := matrix.ConnectWithToken(ctx, synapseURL, acc.UserID, acc.SynapseAccessToken, log)
		if err != nil {
			return nil, false, fmt.Errorf("connect Synapse with access token: %w", err)
		}
		return cli, false, nil
	}
	cli, _, err := matrix.LoginPassword(ctx, synapseURL, acc.UserID, acc.SynapsePassword, matrix.DefaultDeviceDisplayName, log)
	if err != nil {
		return nil, false, fmt.Errorf("login Synapse with password: %w", err)
	}
	return cli, true, nil
}

func logoutSynapseSession(ctx context.Context, cli *mautrix.Client, userID string, log *zerolog.Logger) {
	if _, err := cli.Logout(ctx); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("Failed to log out temporary Synapse migration device")
	}
}

func verifyAndExportIdentity(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	acc *config.AccountConfig,
	log *zerolog.Logger,
) (*dump.IdentityData, *extractedBackup, *crypto.CrossSigningPublicKeysCache, error) {
	defaultKeyID, keyMeta, err := mach.SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch SSSS default key data: %w", err)
	}

	ssssKey, verifyErr := keyMeta.VerifyRecoveryKey(defaultKeyID, acc.RecoveryKey)
	if verifyErr != nil && !errors.Is(verifyErr, ssss.ErrUnverifiableKey) {
		return nil, nil, nil, fmt.Errorf("verify recovery key against SSSS metadata: %w", verifyErr)
	}
	if errors.Is(verifyErr, ssss.ErrUnverifiableKey) {
		log.Warn().Str("user_id", acc.UserID).Str("key_id", defaultKeyID).Msg("SSSS key metadata omits MAC; relying on AEAD verification of SSSS payloads")
	}

	seeds, pubKeys, xsErr := verifyCrossSigningKeys(ctx, cli, mach, acc, ssssKey)
	if xsErr != nil {
		return nil, nil, nil, xsErr
	}

	backupData, backupErr := exportBackupAndVerify(ctx, cli, mach, acc.UserID, ssssKey, log)
	if backupErr != nil {
		return nil, nil, nil, backupErr
	}

	rawSSSS, rawErr := collectVerbatimSSSS(ctx, cli, defaultKeyID, backupData.hasSSSSKey)
	if rawErr != nil {
		return nil, nil, nil, rawErr
	}

	identity := &dump.IdentityData{
		UserID:                acc.UserID,
		DefaultSSSSKeyID:      defaultKeyID,
		MasterSeed:            slices.Clone(seeds.MasterKey),
		SelfSigningSeed:       slices.Clone(seeds.SelfSigningKey),
		UserSigningSeed:       slices.Clone(seeds.UserSigningKey),
		MasterPublicKey:       pubKeys.MasterKey.String(),
		SelfSigningPublicKey:  pubKeys.SelfSigningKey.String(),
		UserSigningPublicKey:  pubKeys.UserSigningKey.String(),
		MegolmBackupKey:       slices.Clone(backupData.rawKeyBytes),
		MegolmBackupPublicKey: backupData.publicKey,
		KeyBackupVersion:      backupData.version,
		RawSSSSAccountData:    rawSSSS,
	}
	return identity, backupData, pubKeys, nil
}

func verifyCrossSigningKeys(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	acc *config.AccountConfig,
	ssssKey *ssss.Key,
) (crypto.CrossSigningSeeds, *crypto.CrossSigningPublicKeysCache, error) {
	if err := mach.FetchCrossSigningKeysFromSSSS(ctx, ssssKey); err != nil {
		return crypto.CrossSigningSeeds{}, nil, fmt.Errorf("decrypt cross-signing keys from SSSS: %w", err)
	}

	seeds := mach.ExportCrossSigningKeys()
	pubKeys := mach.CrossSigningKeys.PublicKeys()

	uid := id.UserID(acc.UserID)
	queryResp, err := cli.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		Timeout:    keysQueryTimeoutMs,
		DeviceKeys: mautrix.DeviceKeysRequest{uid: {}},
	})
	if err != nil {
		return crypto.CrossSigningSeeds{}, nil, fmt.Errorf("query cross-signing public keys from Synapse: %w", err)
	}

	masterKeys := queryResp.MasterKeys[uid]
	selfKeys := queryResp.SelfSigningKeys[uid]
	userKeys := queryResp.UserSigningKeys[uid]
	serverMaster := masterKeys.FirstKey()
	serverSelf := selfKeys.FirstKey()
	serverUser := userKeys.FirstKey()
	if serverMaster != pubKeys.MasterKey || serverSelf != pubKeys.SelfSigningKey || serverUser != pubKeys.UserSigningKey {
		return crypto.CrossSigningSeeds{}, nil, fmt.Errorf(
			"%w: master=(server %q vs local %q), self=(server %q vs local %q), user=(server %q vs local %q)",
			ErrCrossSigningMismatch,
			serverMaster,
			pubKeys.MasterKey,
			serverSelf,
			pubKeys.SelfSigningKey,
			serverUser,
			pubKeys.UserSigningKey,
		)
	}

	return seeds, pubKeys, nil
}

func exportBackupAndVerify(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	userID string,
	ssssKey *ssss.Key,
	log *zerolog.Logger,
) (*extractedBackup, error) {
	out := &extractedBackup{
		roomKeys: &dump.RoomKeysData{
			UserID: userID,
			Rooms:  make(map[string]dump.RoomKeyBackupRoom),
		},
		sessionsByRoom: make(map[id.RoomID]map[id.SessionID]backup.EncryptedSessionData[backup.MegolmSessionData]),
	}

	rawKeyBytes, decKeyErr := mach.SSSS.GetDecryptedAccountData(ctx, event.AccountDataMegolmBackupKey, ssssKey)
	if decKeyErr != nil {
		if !isNotFoundErr(decKeyErr) {
			return nil, fmt.Errorf("decrypt %s from SSSS: %w", event.AccountDataMegolmBackupKey.Type, decKeyErr)
		}
		return handleMissingSSSSBackupKey(ctx, cli, userID, out, log)
	}

	out.hasSSSSKey = true
	megolmKey, keyErr := backup.MegolmBackupKeyFromBytes(rawKeyBytes)
	if keyErr != nil {
		return nil, fmt.Errorf("parse megolm backup private key: %w", keyErr)
	}
	derivedPub := id.Ed25519(base64.RawStdEncoding.EncodeToString(megolmKey.PublicKey().Bytes()))
	out.megolmKey = megolmKey
	out.rawKeyBytes = rawKeyBytes
	out.publicKey = derivedPub.String()

	versionInfo, verErr := cli.GetKeyBackupLatestVersion(ctx)
	if verErr != nil {
		if isNotFoundErr(verErr) {
			log.Warn().Str("user_id", userID).Msg("SSSS holds m.megolm_backup.v1 but Synapse has no active room_keys version; skipping room_keys export")
			return out, nil
		}
		return nil, fmt.Errorf("fetch key backup latest version: %w", verErr)
	}
	if versionInfo.Algorithm != id.KeyBackupAlgorithmMegolmBackupV1 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedBackupAlg, versionInfo.Algorithm)
	}
	if versionInfo.AuthData.PublicKey != derivedPub {
		return nil, fmt.Errorf("%w: server=%s derived=%s", ErrBackupKeyMismatch, versionInfo.AuthData.PublicKey, derivedPub)
	}
	out.version = string(versionInfo.Version)

	rawBackup, backupErr := cli.GetKeyBackup(ctx, versionInfo.Version)
	if backupErr != nil {
		return nil, fmt.Errorf("download key backup version %s: %w", versionInfo.Version, backupErr)
	}
	if rawBackup != nil {
		if convErr := populateRoomKeys(out, rawBackup); convErr != nil {
			return nil, convErr
		}
	}

	if testErr := testDecryptFirstBackupSession(out.sessionsByRoom, megolmKey); testErr != nil {
		return nil, testErr
	}
	return out, nil
}

func handleMissingSSSSBackupKey(
	ctx context.Context,
	cli *mautrix.Client,
	userID string,
	out *extractedBackup,
	log *zerolog.Logger,
) (*extractedBackup, error) {
	versionInfo, verErr := cli.GetKeyBackupLatestVersion(ctx)
	if verErr != nil {
		if isNotFoundErr(verErr) {
			log.Warn().Str("user_id", userID).Msg("Online key backup is not configured on Synapse (404); skipping room_keys export")
			return out, nil
		}
		return nil, fmt.Errorf("check key backup latest version after missing SSSS backup key: %w", verErr)
	}
	return nil, fmt.Errorf("%w (server version %s)", ErrMissingBackupKey, versionInfo.Version)
}

func populateRoomKeys(
	out *extractedBackup,
	rawBackup *mautrix.RespRoomKeys[backup.EncryptedSessionData[backup.MegolmSessionData]],
) error {
	for roomID, roomData := range rawBackup.Rooms {
		roomSessions := make(map[string]dump.RoomKeySession, len(roomData.Sessions))
		encSessions := make(map[id.SessionID]backup.EncryptedSessionData[backup.MegolmSessionData], len(roomData.Sessions))
		for sessID, sess := range roomData.Sessions {
			sessionCopy := sess.SessionData
			encodedSessionData, marshalErr := jsonMarshal(&sessionCopy)
			if marshalErr != nil {
				return fmt.Errorf("encode backup session %s in %s: %w", sessID, roomID, marshalErr)
			}
			roomSessions[string(sessID)] = dump.RoomKeySession{
				SessionData:       encodedSessionData,
				FirstMessageIndex: sess.FirstMessageIndex,
				ForwardedCount:    sess.ForwardedCount,
				IsVerified:        sess.IsVerified,
			}
			encSessions[sessID] = sess.SessionData
		}
		out.roomKeys.Rooms[string(roomID)] = dump.RoomKeyBackupRoom{Sessions: roomSessions}
		out.sessionsByRoom[roomID] = encSessions
	}
	return nil
}

func testDecryptFirstBackupSession(
	sessionsByRoom map[id.RoomID]map[id.SessionID]backup.EncryptedSessionData[backup.MegolmSessionData],
	megolmKey *backup.MegolmBackupKey,
) error {
	roomIDs := make([]id.RoomID, 0, len(sessionsByRoom))
	for roomID := range sessionsByRoom {
		roomIDs = append(roomIDs, roomID)
	}
	slices.Sort(roomIDs)

	for _, roomID := range roomIDs {
		sessions := sessionsByRoom[roomID]
		if len(sessions) == 0 {
			continue
		}
		sessIDs := make([]id.SessionID, 0, len(sessions))
		for sessID := range sessions {
			sessIDs = append(sessIDs, sessID)
		}
		slices.Sort(sessIDs)

		firstSessID := sessIDs[0]
		encSession := sessions[firstSessID]
		decrypted, decErr := decryptBackupSession(encSession, megolmKey)
		if decErr != nil {
			return fmt.Errorf("%w (%s/%s): %w", ErrBackupCorrupted, roomID, firstSessID, decErr)
		}
		igs, impErr := olm.InboundGroupSessionImport([]byte(decrypted.SessionKey))
		if impErr != nil {
			return fmt.Errorf("%w (%s/%s import): %w", ErrBackupCorrupted, roomID, firstSessID, impErr)
		}
		if igs.ID() != firstSessID {
			return fmt.Errorf("%w: session ID mismatch (%s != %s)", ErrBackupCorrupted, igs.ID(), firstSessID)
		}
		return nil
	}
	return nil
}

func decryptBackupSession(
	encSession backup.EncryptedSessionData[backup.MegolmSessionData],
	megolmKey *backup.MegolmBackupKey,
) (*backup.MegolmSessionData, error) {
	clone := encSession
	clone.Ciphertext = slices.Clone(encSession.Ciphertext)
	clone.MAC = slices.Clone(encSession.MAC)
	decrypted, err := clone.Decrypt(megolmKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt backup session: %w", err)
	}
	return decrypted, nil
}

func collectVerbatimSSSS(
	ctx context.Context,
	cli *mautrix.Client,
	defaultKeyID string,
	includeBackupKey bool,
) (map[string]json.RawMessage, error) {
	eventNames := []string{
		event.AccountDataSecretStorageDefaultKey.Type,
		event.AccountDataSecretStorageKey.Type + "." + defaultKeyID,
		event.AccountDataCrossSigningMaster.Type,
		event.AccountDataCrossSigningSelf.Type,
		event.AccountDataCrossSigningUser.Type,
	}
	if includeBackupKey {
		eventNames = append(eventNames, event.AccountDataMegolmBackupKey.Type)
	}

	rawMap := make(map[string]json.RawMessage, len(eventNames))
	for _, name := range eventNames {
		var payload json.RawMessage
		if err := cli.GetAccountData(ctx, name, &payload); err != nil {
			return nil, fmt.Errorf("fetch raw SSSS account data %s: %w", name, err)
		}
		rawMap[name] = payload
	}
	return rawMap, nil
}

func exportProfileData(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	userID string,
	directRoomSet map[string]struct{},
	log *zerolog.Logger,
) (*dump.ProfileData, error) {
	displayName, avatarRef, profErr := fetchUserProfile(ctx, cli, store, userID, log)
	if profErr != nil {
		return nil, profErr
	}
	profile := &dump.ProfileData{
		UserID:      userID,
		DisplayName: displayName,
		Avatar:      avatarRef,
	}

	var directContent event.DirectChatsEventContent
	if err := cli.GetAccountData(ctx, event.AccountDataDirectChats.Type, &directContent); err != nil {
		if !isNotFoundErr(err) {
			return nil, fmt.Errorf("fetch m.direct account data: %w", err)
		}
	} else if len(directContent) > 0 {
		directMap := make(map[string][]string, len(directContent))
		for partner, rooms := range directContent {
			roomStrs := make([]string, 0, len(rooms))
			for _, roomID := range rooms {
				roomStrs = append(roomStrs, string(roomID))
				directRoomSet[string(roomID)] = struct{}{}
			}
			directMap[string(partner)] = roomStrs
		}
		profile.Direct = directMap
	}

	var ignoredRaw json.RawMessage
	if err := cli.GetAccountData(ctx, event.AccountDataIgnoredUserList.Type, &ignoredRaw); err != nil {
		if !isNotFoundErr(err) {
			return nil, fmt.Errorf("fetch m.ignored_user_list account data: %w", err)
		}
	} else if len(ignoredRaw) > 0 {
		profile.IgnoredUsers = ignoredRaw
	}

	return profile, nil
}

func fetchUserProfile(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	userID string,
	log *zerolog.Logger,
) (string, *dump.MediaRef, error) {
	profResp, err := cli.GetProfile(ctx, id.UserID(userID))
	if err != nil {
		if isNotFoundErr(err) {
			log.Warn().Str("user_id", userID).Msg("User profile returned 404; continuing with empty display name and avatar")
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("fetch user profile: %w", err)
	}
	if profResp == nil {
		return "", nil, nil
	}
	if profResp.AvatarURL.IsEmpty() {
		return profResp.DisplayName, nil, nil
	}
	avatarRef, found, dlErr := downloadOptionalMedia(ctx, cli, store, profResp.AvatarURL, "", "", log)
	if dlErr != nil {
		return "", nil, fmt.Errorf("download user avatar: %w", dlErr)
	}
	if !found {
		return profResp.DisplayName, nil, nil
	}
	return profResp.DisplayName, &avatarRef, nil
}

func exportJoinedRooms(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	serverName string,
	userID string,
	allowlisted map[string]struct{},
	observationsByRoom map[string]*classifier.RoomObservation,
	log *zerolog.Logger,
) (*collectedRooms, error) {
	joinedResp, err := cli.JoinedRooms(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch joined rooms: %w", err)
	}

	out := &collectedRooms{
		roomTags:      make(map[string]map[string]dump.RoomTagEntry),
		joinedRoomIDs: joinedResp.JoinedRooms,
	}
	extCandidateSet := make(map[string]struct{})

	for _, roomID := range joinedResp.JoinedRooms {
		roomIDStr := roomID.String()
		obs, exists := observationsByRoom[roomIDStr]
		if !exists {
			builtObs, buildErr := buildRoomObservation(ctx, cli, store, roomID, log)
			if buildErr != nil {
				return nil, fmt.Errorf("inspect room %s state: %w", roomIDStr, buildErr)
			}
			observationsByRoom[roomIDStr] = builtObs
			obs = builtObs
		}
		if !slices.Contains(obs.JoinedLocalUsers, userID) {
			obs.JoinedLocalUsers = append(obs.JoinedLocalUsers, userID)
		}

		collectExternalRoomCandidates(obs.StateEvents, serverName, allowlisted, extCandidateSet)

		tags, tagErr := fetchRoomTags(ctx, cli, roomID)
		if tagErr != nil {
			return nil, fmt.Errorf("fetch room tags for %s: %w", roomIDStr, tagErr)
		}
		if len(tags) > 0 {
			out.roomTags[roomIDStr] = tags
		}
	}

	if len(extCandidateSet) > 0 {
		out.extCandidates = make([]string, 0, len(extCandidateSet))
		for candidate := range extCandidateSet {
			out.extCandidates = append(out.extCandidates, candidate)
		}
		sort.Strings(out.extCandidates)
	}
	return out, nil
}

func buildRoomObservation(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	roomID id.RoomID,
	log *zerolog.Logger,
) (*classifier.RoomObservation, error) {
	rawEvents, err := cli.StateAsArray(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("fetch room state array: %w", err)
	}

	stateEvents := make([]classifier.StateEvent, 0, len(rawEvents))
	var avatarMXC id.ContentURIString
	var avatarMime string

	for _, evt := range rawEvents {
		rawContent := evt.Content.VeryRaw
		if len(rawContent) == 0 {
			rawContent = json.RawMessage("{}")
		}
		stateEvents = append(stateEvents, classifier.StateEvent{
			Type:     evt.Type.Type,
			StateKey: evt.GetStateKey(),
			Sender:   evt.Sender.String(),
			Content:  rawContent,
		})
		if evt.Type == event.StateRoomAvatar {
			var av event.RoomAvatarEventContent
			if json.Unmarshal(rawContent, &av) == nil && av.URL != "" {
				avatarMXC = av.URL
				if av.Info != nil {
					avatarMime = av.Info.MimeType
				}
			}
		}
	}

	obs := &classifier.RoomObservation{
		RoomID:      roomID.String(),
		StateEvents: stateEvents,
	}
	if avatarMXC == "" {
		return obs, nil
	}

	parsedURI, parseErr := avatarMXC.Parse()
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("room_id", roomID.String()).Str("avatar_url", string(avatarMXC)).Msg("Skipping room avatar with invalid MXC URI")
		return obs, nil
	}
	ref, found, dlErr := downloadOptionalMedia(ctx, cli, store, parsedURI, avatarMime, "", log)
	if dlErr != nil {
		return nil, fmt.Errorf("download room %s avatar: %w", roomID, dlErr)
	}
	if found {
		obs.AvatarMXC = ref.OriginalMXC
		obs.AvatarSHA256 = ref.SHA256
		obs.AvatarType = ref.ContentType
		obs.AvatarSize = ref.Size
	}
	return obs, nil
}

func collectExternalRoomCandidates(
	events []classifier.StateEvent,
	serverName string,
	allowlisted map[string]struct{},
	extCandidateSet map[string]struct{},
) {
	roomMembers := make([]string, 0)
	for i := range events {
		ev := &events[i]
		if isBridgeStateEvent(ev, allowlisted) {
			return
		}
		if ev.Type == event.StateMember.Type && ev.StateKey != "" {
			var mc struct {
				Membership string `json:"membership"`
			}
			if json.Unmarshal(ev.Content, &mc) == nil && mc.Membership == string(event.MembershipJoin) {
				roomMembers = append(roomMembers, ev.StateKey)
			}
		}
	}
	for _, member := range roomMembers {
		if extractServerName(member) != serverName {
			extCandidateSet[member] = struct{}{}
		}
	}
}

func isBridgeStateEvent(ev *classifier.StateEvent, allowlisted map[string]struct{}) bool {
	if ev.Type == event.StateBridge.Type || ev.Type == event.StateHalfShotBridge.Type || strings.HasPrefix(ev.Type, "fi.mau.") {
		return true
	}
	if ev.Type != event.StateElementFunctionalMembers.Type {
		return false
	}
	var fm event.ElementFunctionalMembersContent
	if json.Unmarshal(ev.Content, &fm) != nil {
		return false
	}
	for _, svc := range fm.ServiceMembers {
		if _, ok := allowlisted[svc.String()]; !ok {
			return true
		}
	}
	return false
}

func fetchRoomTags(ctx context.Context, cli *mautrix.Client, roomID id.RoomID) (map[string]dump.RoomTagEntry, error) {
	tagResp, err := cli.GetTags(ctx, roomID)
	if err != nil {
		if isNotFoundErr(err) {
			return map[string]dump.RoomTagEntry{}, nil
		}
		return nil, fmt.Errorf("get room tags: %w", err)
	}
	if len(tagResp.Tags) == 0 {
		return map[string]dump.RoomTagEntry{}, nil
	}
	out := make(map[string]dump.RoomTagEntry, len(tagResp.Tags))
	for tagName, meta := range tagResp.Tags {
		var orderPtr *float64
		if meta.Order != "" {
			if val, parseErr := meta.Order.Float64(); parseErr == nil {
				orderVal := val
				orderPtr = &orderVal
			}
		}
		out[string(tagName)] = dump.RoomTagEntry{Order: orderPtr}
	}
	return out, nil
}

func exportTrustGraph(
	ctx context.Context,
	cli *mautrix.Client,
	cfg *config.Config,
	acc *config.AccountConfig,
	userSigningPub id.Ed25519,
	extCandidates []string,
	directMap map[string][]string,
	log *zerolog.Logger,
) (*dump.TrustGraphData, error) {
	ownerID := id.UserID(acc.UserID)

	localCandidates := make([]id.UserID, 0, len(cfg.Accounts))
	for i := range cfg.Accounts {
		other := cfg.Accounts[i].UserID
		if other != acc.UserID {
			localCandidates = append(localCandidates, id.UserID(other))
		}
	}

	contacts, localErr := queryTrustedContacts(ctx, cli, ownerID, userSigningPub, localCandidates, true, log)
	if localErr != nil {
		return nil, fmt.Errorf("query local trust contacts: %w", localErr)
	}

	extSet := make(map[string]struct{}, len(extCandidates)+len(directMap))
	for _, c := range extCandidates {
		extSet[c] = struct{}{}
	}
	for partner := range directMap {
		if extractServerName(partner) != cfg.ServerName && validator.ValidateUserID(partner) == nil {
			extSet[partner] = struct{}{}
		}
	}
	if len(extSet) > 0 {
		extIDs := make([]id.UserID, 0, len(extSet))
		for candidate := range extSet {
			extIDs = append(extIDs, id.UserID(candidate))
		}
		slices.Sort(extIDs)
		extContacts, extErr := queryTrustedContacts(ctx, cli, ownerID, userSigningPub, extIDs, false, log)
		if extErr != nil {
			return nil, fmt.Errorf("query external trust contacts: %w", extErr)
		}
		contacts = append(contacts, extContacts...)
	}

	sort.Slice(contacts, func(i, j int) bool {
		return contacts[i].UserID < contacts[j].UserID
	})

	return &dump.TrustGraphData{
		UserID:   acc.UserID,
		Contacts: contacts,
	}, nil
}

func queryTrustedContacts(
	ctx context.Context,
	cli *mautrix.Client,
	ownerID id.UserID,
	userSigningPub id.Ed25519,
	candidates []id.UserID,
	isLocal bool,
	log *zerolog.Logger,
) ([]dump.TrustedContact, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	reqDeviceKeys := make(mautrix.DeviceKeysRequest, len(candidates))
	for _, candidate := range candidates {
		reqDeviceKeys[candidate] = []id.DeviceID{}
	}

	resp, err := cli.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		Timeout:    keysQueryTimeoutMs,
		DeviceKeys: reqDeviceKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("query candidate keys: %w", err)
	}
	if len(resp.Failures) > 0 {
		for domain := range resp.Failures {
			log.Warn().Str("owner", ownerID.String()).Str("failed_server", domain).Msg("Remote server key query failed while collecting trust graph")
		}
	}

	trusted := make([]dump.TrustedContact, 0)
	for _, candidate := range candidates {
		mk, exists := resp.MasterKeys[candidate]
		if !exists {
			continue
		}
		masterPub := mk.FirstKey()
		if masterPub == "" {
			continue
		}
		verified, sigErr := signatures.VerifySignatureJSON(&mk, ownerID, userSigningPub.String(), userSigningPub)
		if sigErr == nil && verified {
			trusted = append(trusted, dump.TrustedContact{
				UserID:    candidate.String(),
				MasterKey: masterPub.String(),
				Local:     isLocal,
			})
		}
	}
	return trusted, nil
}

func persistExportOutputs(
	store *dump.Store,
	cfg *config.Config,
	manifest *dump.ManifestState,
	corpus *classifier.Corpus,
	exportedAccounts []*exportedAccountState,
	notesByRoom map[string][]dump.NoteEntry,
	allowlisted map[string]struct{},
) error {
	for i := range corpus.LocalRooms {
		if corpus.LocalRooms[i].Category == dump.RoomCategoryNotes {
			if notes, ok := notesByRoom[corpus.LocalRooms[i].OldRoomID]; ok {
				corpus.LocalRooms[i].Notes = notes
			}
		}
	}

	for _, accState := range exportedAccounts {
		if err := writeSingleAccountDump(store, cfg.ServerName, corpus.BridgeOrOrphanRooms, allowlisted, accState); err != nil {
			return err
		}
	}

	if err := store.WriteLocalRooms(&dump.LocalRoomsData{Rooms: corpus.LocalRooms}); err != nil {
		return fmt.Errorf("write local rooms: %w", err)
	}
	if err := store.WriteFederatedRooms(&dump.FederatedRoomsData{Rooms: corpus.FederatedRooms}); err != nil {
		return fmt.Errorf("write federated rooms: %w", err)
	}

	updatedManifest := &dump.ManifestState{
		LocalRoomMap:           maps.Clone(manifest.LocalRoomMap),
		ProvisionedUsers:       maps.Clone(manifest.ProvisionedUsers),
		ServerName:             cfg.ServerName,
		LocalRoomVersion:       cfg.LocalRoomVersion,
		ExportedAt:             nowUTC().Format(time.RFC3339),
		Phase:                  dump.PhaseExported,
		ServerSigningKeyID:     manifest.ServerSigningKeyID,
		ServerSigningPublicKey: manifest.ServerSigningPublicKey,
	}
	if err := store.WriteManifest(updatedManifest); err != nil {
		return fmt.Errorf("write manifest state: %w", err)
	}
	return nil
}

func writeSingleAccountDump(
	store *dump.Store,
	serverName string,
	excludedRooms map[string]struct{},
	allowlisted map[string]struct{},
	accState *exportedAccountState,
) error {
	if len(accState.profile.Direct) > 0 {
		accState.profile.Direct = classifier.FilterDirectMap(accState.profile.Direct, allowlisted, serverName, excludedRooms)
	}
	if len(accState.profile.RoomTags) > 0 {
		for roomID := range excludedRooms {
			delete(accState.profile.RoomTags, roomID)
		}
		if len(accState.profile.RoomTags) == 0 {
			accState.profile.RoomTags = nil
		}
	}
	filteredKeys := classifier.FilterRoomKeys(accState.roomKeys, excludedRooms)

	if err := store.WriteIdentity(accState.userID, accState.identity); err != nil {
		return fmt.Errorf("write identity for %s: %w", accState.userID, err)
	}
	if err := store.WriteRoomKeys(accState.userID, filteredKeys); err != nil {
		return fmt.Errorf("write room keys for %s: %w", accState.userID, err)
	}
	if err := store.WriteProfile(accState.userID, accState.profile); err != nil {
		return fmt.Errorf("write profile for %s: %w", accState.userID, err)
	}
	if err := store.WriteTrustGraph(accState.userID, accState.trustGraph); err != nil {
		return fmt.Errorf("write trust graph for %s: %w", accState.userID, err)
	}
	return nil
}

func downloadOptionalMedia(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	mxc id.ContentURI,
	fallbackContentType string,
	filename string,
	log *zerolog.Logger,
) (dump.MediaRef, bool, error) {
	data, contentType, err := matrix.DownloadMediaWithFallback(ctx, cli, mxc)
	if err != nil {
		if isNotFoundErr(err) {
			log.Warn().Str("mxc", mxc.String()).Msg("Media asset returned 404 on Synapse; skipping attachment")
			return dump.MediaRef{}, false, nil
		}
		return dump.MediaRef{}, false, fmt.Errorf("download %s: %w", mxc.String(), err)
	}
	if contentType == "" {
		contentType = fallbackContentType
	}
	ref, saveErr := store.SaveMedia(mxc.String(), contentType, filename, data)
	if saveErr != nil {
		return dump.MediaRef{}, false, fmt.Errorf("save media %s: %w", mxc.String(), saveErr)
	}
	return *ref, true, nil
}

func isNotFoundErr(err error) bool {
	return matrix.IsHTTPStatus(err, http.StatusNotFound) || matrix.IsMatrixErrCode(err, mautrix.MNotFound.ErrCode)
}

func extractServerName(userID string) string {
	trimmed := strings.TrimPrefix(userID, "@")
	_, server, ok := strings.Cut(trimmed, ":")
	if !ok {
		return ""
	}
	return server
}
