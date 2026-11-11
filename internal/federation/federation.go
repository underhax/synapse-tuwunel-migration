// Package federation rejoins migrated users into federated Matrix rooms and re-signs verified external contacts.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
	"github.com/underhax/synapse-tuwunel-migration/internal/signingkey"
)

const keysQueryTimeoutMs = 5000

// Sentinel errors returned when federation sync preconditions or external key verification fail.
var (
	ErrNilConfig         = errors.New("config must not be nil")
	ErrNilStore          = errors.New("dump store must not be nil")
	ErrMissingManifest   = errors.New("manifest_state.json missing; run export and import-local before federate-sync")
	ErrMissingMember     = errors.New("federated room local member missing from configured accounts")
	ErrInvalidLocalSeed  = errors.New("invalid exported cross-signing seed payload")
	ErrMasterKeyMismatch = errors.New("external contact master key does not match exported trust graph")
)

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

var (
	newOlmMachine = matrix.NewOlmMachine
	writeManifest = defaultWriteManifest
	writeSession  = defaultWriteSession
)

type fedAccount struct {
	cli         *mautrix.Client
	mach        *crypto.OlmMachine
	profile     *dump.ProfileData
	joinedRooms map[string]struct{}
	userID      string
}

type syncStats struct {
	joined              int
	skippedJoined       int
	failedJoins         int
	signedContacts      int
	skippedContacts     int
	unreachableContacts int
}

// Run rejoins exported federated rooms on Tuwunel and restores user-signing signatures for external contacts.
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
	if err := cfg.ValidateForMode(config.ModeFederateSync); err != nil {
		return fmt.Errorf("validate federate-sync config: %w", err)
	}

	manifest, err := loadFedManifest(store)
	if err != nil {
		return err
	}
	if keyErr := verifyFederationSigningKey(ctx, cfg, manifest, log); keyErr != nil {
		return keyErr
	}

	fedRooms, err := store.ReadFederatedRooms()
	if err != nil {
		return fmt.Errorf("read federated_rooms.json: %w", err)
	}

	accountsByID, orderedAccounts, err := prepareFedAccounts(ctx, cfg, store, log)
	if err != nil {
		return err
	}

	var stats syncStats
	if err := syncFederatedRooms(ctx, fedRooms.Rooms, accountsByID, &stats, log); err != nil {
		return err
	}

	if err := restoreExternalTrustGraph(ctx, store, orderedAccounts, &stats, log); err != nil {
		return err
	}

	manifest.Phase = dump.PhaseFederatedSync
	if err := writeManifest(store, manifest); err != nil {
		return fmt.Errorf("write final manifest state: %w", err)
	}

	log.Info().
		Int("accounts", len(orderedAccounts)).
		Int("joined_federated_rooms", stats.joined).
		Int("skipped_already_joined", stats.skippedJoined).
		Int("failed_federated_joins", stats.failedJoins).
		Int("signed_external_contacts", stats.signedContacts).
		Int("skipped_signed_contacts", stats.skippedContacts).
		Int("unreachable_external_contacts", stats.unreachableContacts).
		Msg("Tuwunel federation sync completed")

	return nil
}

func loadFedManifest(store *dump.Store) (*dump.ManifestState, error) {
	manifest, err := store.ReadManifest()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissingManifest
		}
		return nil, fmt.Errorf("read manifest_state.json: %w", err)
	}
	return manifest, nil
}

func verifyFederationSigningKey(
	ctx context.Context,
	cfg *config.Config,
	manifest *dump.ManifestState,
	log *zerolog.Logger,
) error {
	if _, err := signingkey.VerifyServerKeyState(ctx, nil, cfg.TuwunelURL, cfg.ServerName, manifest, true); err != nil {
		return fmt.Errorf("verify Tuwunel federation server key: %w", err)
	}
	log.Debug().Str("key_id", manifest.ServerSigningKeyID).Msg("Verified live Tuwunel /_matrix/key/v2/server key for federation")
	return nil
}

func prepareFedAccounts(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	log *zerolog.Logger,
) (map[string]*fedAccount, []*fedAccount, error) {
	byID := make(map[string]*fedAccount, len(cfg.Accounts))
	ordered := make([]*fedAccount, 0, len(cfg.Accounts))

	for i := range cfg.Accounts {
		acc := &cfg.Accounts[i]
		prepared, err := prepareSingleFedAccount(ctx, cfg, store, acc, log)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare account %s: %w", acc.UserID, err)
		}
		byID[acc.UserID] = prepared
		ordered = append(ordered, prepared)
	}
	return byID, ordered, nil
}

func prepareSingleFedAccount(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	acc *config.AccountConfig,
	log *zerolog.Logger,
) (*fedAccount, error) {
	cli, err := authenticateAccount(ctx, cfg, store, acc, log)
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
	seeds := crypto.CrossSigningSeeds{
		MasterKey:      slices.Clone(identity.MasterSeed),
		SelfSigningKey: slices.Clone(identity.SelfSigningSeed),
		UserSigningKey: slices.Clone(identity.UserSigningSeed),
	}
	if impErr := mach.ImportCrossSigningKeys(seeds); impErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidLocalSeed, impErr)
	}

	profile, err := store.ReadProfile(acc.UserID)
	if err != nil {
		return nil, fmt.Errorf("read profile.json: %w", err)
	}

	joinedResp, err := cli.JoinedRooms(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch joined rooms: %w", err)
	}
	joinedSet := make(map[string]struct{})
	if joinedResp != nil {
		joinedSet = make(map[string]struct{}, len(joinedResp.JoinedRooms))
		for _, rid := range joinedResp.JoinedRooms {
			joinedSet[rid.String()] = struct{}{}
		}
	}

	return &fedAccount{
		cli:         cli,
		mach:        mach,
		profile:     profile,
		joinedRooms: joinedSet,
		userID:      acc.UserID,
	}, nil
}

func authenticateAccount(
	ctx context.Context,
	cfg *config.Config,
	store *dump.Store,
	acc *config.AccountConfig,
	log *zerolog.Logger,
) (*mautrix.Client, error) {
	sess, err := store.ReadSession(acc.UserID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read session.json: %w", err)
	}
	if err == nil && sess.AccessToken != "" {
		cli, _, connErr := matrix.ConnectWithToken(ctx, cfg.TuwunelURL, acc.UserID, sess.AccessToken, log)
		if connErr == nil {
			return cli, nil
		}
		if !isUnauthorizedErr(connErr) {
			return nil, fmt.Errorf("validate saved Tuwunel session: %w", connErr)
		}
		log.Warn().Str("user_id", acc.UserID).Msg("Saved Tuwunel session token was rejected; creating a new temporary login")
	}

	cli, _, loginErr := matrix.LoginPassword(ctx, cfg.TuwunelURL, acc.UserID, acc.TuwunelPassword, matrix.DefaultDeviceDisplayName, log)
	if loginErr != nil {
		return nil, fmt.Errorf("login on Tuwunel: %w", loginErr)
	}
	if writeErr := writeSession(store, acc.UserID, &dump.SessionData{
		UserID:        acc.UserID,
		HomeserverURL: cfg.TuwunelURL,
		AccessToken:   cli.AccessToken,
		DeviceID:      cli.DeviceID.String(),
	}); writeErr != nil {
		return nil, writeErr
	}
	return cli, nil
}

func syncFederatedRooms(
	ctx context.Context,
	rooms []dump.FederatedRoom,
	accountsByID map[string]*fedAccount,
	stats *syncStats,
	log *zerolog.Logger,
) error {
	for i := range rooms {
		room := &rooms[i]
		if err := syncSingleFederatedRoom(ctx, room, accountsByID, stats, log); err != nil {
			return err
		}
	}
	return nil
}

func syncSingleFederatedRoom(
	ctx context.Context,
	room *dump.FederatedRoom,
	accountsByID map[string]*fedAccount,
	stats *syncStats,
	log *zerolog.Logger,
) error {
	for _, userID := range room.JoinedLocalUsers {
		acc, ok := accountsByID[userID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingMember, userID)
		}

		joined, err := ensureUserJoinedRoom(ctx, acc, room, stats, log)
		if err != nil {
			return err
		}
		if !joined {
			continue
		}

		desiredTags := acc.profile.RoomTags[room.RoomID]
		if len(desiredTags) > 0 {
			if err := applyFederatedRoomTags(ctx, acc.cli, id.RoomID(room.RoomID), desiredTags); err != nil {
				return fmt.Errorf("apply federated room tags for %s in %s: %w", acc.userID, room.RoomID, err)
			}
		}
	}
	return nil
}

func ensureUserJoinedRoom(
	ctx context.Context,
	acc *fedAccount,
	room *dump.FederatedRoom,
	stats *syncStats,
	log *zerolog.Logger,
) (bool, error) {
	if _, alreadyJoined := acc.joinedRooms[room.RoomID]; alreadyJoined {
		stats.skippedJoined++
		return true, nil
	}

	_, joinErr := acc.cli.JoinRoom(ctx, room.RoomID, &mautrix.ReqJoinRoom{
		Via: slices.Clone(room.ViaServers),
	})
	if joinErr != nil {
		if ctx.Err() != nil {
			return false, fmt.Errorf("rejoin federated room %s canceled: %w", room.RoomID, ctx.Err())
		}
		log.Warn().
			Err(joinErr).
			Str("user_id", acc.userID).
			Str("room_id", room.RoomID).
			Strs("via_servers", room.ViaServers).
			Msg("Failed to rejoin federated room via remote homeservers; continuing")
		stats.failedJoins++
		return false, nil
	}

	acc.joinedRooms[room.RoomID] = struct{}{}
	stats.joined++
	return true, nil
}

func applyFederatedRoomTags(
	ctx context.Context,
	cli *mautrix.Client,
	roomID id.RoomID,
	desired map[string]dump.RoomTagEntry,
) error {
	existing, err := cli.GetTags(ctx, roomID)
	if err != nil && !isNotFoundErr(err) {
		return fmt.Errorf("fetch existing room tags: %w", err)
	}

	tagNames := make([]string, 0, len(desired))
	for name := range desired {
		tagNames = append(tagNames, name)
	}
	sort.Strings(tagNames)

	for _, name := range tagNames {
		entry := desired[name]
		if tagAlreadyMatches(existing.Tags, name, entry.Order) {
			continue
		}
		var meta event.TagMetadata
		if entry.Order != nil {
			meta.Order = json.Number(strconv.FormatFloat(*entry.Order, 'f', -1, 64))
		}
		if err := cli.AddTagWithCustomData(ctx, roomID, event.RoomTag(name), &meta); err != nil {
			return fmt.Errorf("add tag %s: %w", name, err)
		}
	}
	return nil
}

func tagAlreadyMatches(existing event.Tags, name string, desiredOrder *float64) bool {
	if len(existing) == 0 {
		return false
	}
	meta, ok := existing[event.RoomTag(name)]
	if !ok {
		return false
	}
	if desiredOrder == nil {
		return meta.Order == ""
	}
	if meta.Order == "" {
		return false
	}
	existingOrder, err := meta.Order.Float64()
	if err != nil {
		return false
	}
	return existingOrder == *desiredOrder
}

func restoreExternalTrustGraph(
	ctx context.Context,
	store *dump.Store,
	orderedAccounts []*fedAccount,
	stats *syncStats,
	log *zerolog.Logger,
) error {
	for _, acc := range orderedAccounts {
		trustGraph, err := store.ReadTrustGraph(acc.userID)
		if err != nil {
			return fmt.Errorf("read trust_graph.json for %s: %w", acc.userID, err)
		}
		if err := signExternalContacts(ctx, acc, trustGraph.Contacts, stats, log); err != nil {
			return fmt.Errorf("restore external trust signatures for %s: %w", acc.userID, err)
		}
	}
	return nil
}

func signExternalContacts(
	ctx context.Context,
	acc *fedAccount,
	contacts []dump.TrustedContact,
	stats *syncStats,
	log *zerolog.Logger,
) error {
	reqDevices := make(mautrix.DeviceKeysRequest)
	var extTargets []dump.TrustedContact
	for _, contact := range contacts {
		if contact.Local || contact.UserID == acc.userID {
			continue
		}
		extTargets = append(extTargets, contact)
		reqDevices[id.UserID(contact.UserID)] = []id.DeviceID{}
	}
	if len(extTargets) == 0 {
		return nil
	}

	resp, err := acc.cli.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		Timeout:    keysQueryTimeoutMs,
		DeviceKeys: reqDevices,
	})
	if err != nil {
		return fmt.Errorf("query external master keys: %w", err)
	}
	logQueryFailures(acc.userID, resp.Failures, log)

	ownerID := id.UserID(acc.userID)
	userSigningPub := acc.mach.CrossSigningKeys.UserSigningKey.PublicKey()

	for _, contact := range extTargets {
		targetID := id.UserID(contact.UserID)
		mk, exists := resp.MasterKeys[targetID]
		serverMaster := mk.FirstKey()
		if !exists || serverMaster == "" {
			log.Warn().
				Str("owner", acc.userID).
				Str("contact", contact.UserID).
				Msg("External contact master key unavailable over federation; skipping signature")
			stats.unreachableContacts++
			continue
		}
		if serverMaster.String() != contact.MasterKey {
			return fmt.Errorf("%w for %s: server=%q expected=%q", ErrMasterKeyMismatch, contact.UserID, serverMaster, contact.MasterKey)
		}
		alreadySigned, sigErr := signatures.VerifySignatureJSON(&mk, ownerID, userSigningPub.String(), userSigningPub)
		if sigErr == nil && alreadySigned {
			stats.skippedContacts++
			continue
		}
		if err := acc.mach.SignUser(ctx, targetID, serverMaster); err != nil {
			return fmt.Errorf("sign external contact %s: %w", contact.UserID, err)
		}
		stats.signedContacts++
	}
	return nil
}

func logQueryFailures(ownerID string, failures map[string]any, log *zerolog.Logger) {
	if len(failures) == 0 {
		return
	}
	domains := make([]string, 0, len(failures))
	for domain := range failures {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		log.Warn().
			Str("owner", ownerID).
			Str("failed_server", domain).
			Msg("Federated key query returned remote server failure")
	}
}

func isNotFoundErr(err error) bool {
	return matrix.IsHTTPStatus(err, http.StatusNotFound) || matrix.IsMatrixErrCode(err, mautrix.MNotFound.ErrCode)
}

func isUnauthorizedErr(err error) bool {
	return matrix.IsHTTPStatus(err, http.StatusUnauthorized) || matrix.IsMatrixErrCode(err, mautrix.MUnknownToken.ErrCode)
}
