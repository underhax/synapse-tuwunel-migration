// Package cleanup logs out temporary Tuwunel migration devices and removes persisted session tokens.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
)

// Sentinel errors returned when session cleanup preconditions are violated.
var (
	ErrNilConfig = errors.New("config must not be nil")
	ErrNilStore  = errors.New("dump store must not be nil")
)

func defaultRemoveSession(store *dump.Store, userID string) error {
	if err := store.RemoveSession(userID); err != nil {
		return fmt.Errorf("remove session.json for %s: %w", userID, err)
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
	removeSession = defaultRemoveSession
	writeManifest = defaultWriteManifest
)

type cleanupStats struct {
	loggedOut      int
	staleTokens    int
	skippedMissing int
}

// Run logs out active temporary migration devices on Tuwunel and deletes local session.json files.
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
	if err := cfg.ValidateForMode(config.ModeCleanup); err != nil {
		return fmt.Errorf("validate cleanup config: %w", err)
	}

	var stats cleanupStats
	for i := range cfg.Accounts {
		acc := &cfg.Accounts[i]
		if err := cleanupSingleAccount(ctx, cfg.TuwunelURL, store, acc.UserID, &stats, log); err != nil {
			return err
		}
	}

	if err := updateManifestPhase(store); err != nil {
		return err
	}

	log.Info().
		Int("logged_out", stats.loggedOut).
		Int("stale_or_invalidated", stats.staleTokens).
		Int("missing_session", stats.skippedMissing).
		Msg("Tuwunel temporary session cleanup completed")

	return nil
}

func cleanupSingleAccount(
	ctx context.Context,
	tuwunelURL string,
	store *dump.Store,
	userID string,
	stats *cleanupStats,
	log *zerolog.Logger,
) error {
	sess, err := store.ReadSession(userID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			stats.skippedMissing++
			return nil
		}
		return fmt.Errorf("read session.json for %s: %w", userID, err)
	}

	if sess.AccessToken != "" {
		if tokenErr := revokeRemoteSession(ctx, tuwunelURL, userID, sess, stats, log); tokenErr != nil {
			return tokenErr
		}
	}

	return removeSession(store, userID)
}

func revokeRemoteSession(
	ctx context.Context,
	tuwunelURL string,
	userID string,
	sess *dump.SessionData,
	stats *cleanupStats,
	log *zerolog.Logger,
) error {
	cli, _, connErr := matrix.ConnectWithToken(ctx, tuwunelURL, userID, sess.AccessToken, log)
	if connErr != nil {
		if !isUnauthorizedErr(connErr) {
			return fmt.Errorf("verify session for %s: %w", userID, connErr)
		}
		stats.staleTokens++
		log.Info().
			Str("user_id", userID).
			Str("device_id", sess.DeviceID).
			Msg("Temporary migration token already invalidated on Tuwunel; removing session.json")
		return nil
	}

	if _, logoutErr := cli.Logout(ctx); logoutErr != nil {
		if !isAuthOrNotFoundErr(logoutErr) {
			return fmt.Errorf("logout temporary session for %s: %w", userID, logoutErr)
		}
		stats.staleTokens++
		return nil
	}

	stats.loggedOut++
	return nil
}

func updateManifestPhase(store *dump.Store) error {
	manifest, err := store.ReadManifest()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read manifest_state.json after cleanup: %w", err)
	}
	manifest.Phase = dump.PhaseCleanedUp
	if writeErr := writeManifest(store, manifest); writeErr != nil {
		return fmt.Errorf("update manifest phase after cleanup: %w", writeErr)
	}
	return nil
}

func isUnauthorizedErr(err error) bool {
	return matrix.IsHTTPStatus(err, http.StatusUnauthorized) || matrix.IsMatrixErrCode(err, mautrix.MUnknownToken.ErrCode)
}

func isAuthOrNotFoundErr(err error) bool {
	return isUnauthorizedErr(err) || matrix.IsHTTPStatus(err, http.StatusNotFound) || matrix.IsMatrixErrCode(err, mautrix.MNotFound.ErrCode)
}
