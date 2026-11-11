package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/classifier"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
)

const messagesPageLimit = 100

type noteExtractionState struct {
	edits        map[string]*event.MessageEventContent
	reactions    map[string][]string
	reactionSeen map[string]map[string]struct{}
	entries      []dump.NoteEntry
}

func exportAccountSingleUserNotes(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	stateStore *mautrix.MemoryStateStore,
	store *dump.Store,
	cfg *config.Config,
	acc *config.AccountConfig,
	allowlisted map[string]struct{},
	collected *collectedRooms,
	observationsByRoom map[string]*classifier.RoomObservation,
	backupData *extractedBackup,
	notesByRoom map[string][]dump.NoteEntry,
	log *zerolog.Logger,
) error {
	classifyOpts := classifier.ClassifyOptions{
		AllowlistedUsers: allowlisted,
		ServerName:       cfg.ServerName,
		LocalRoomVersion: cfg.LocalRoomVersion,
	}

	for _, roomID := range collected.joinedRoomIDs {
		roomIDStr := roomID.String()
		obs, ok := observationsByRoom[roomIDStr]
		if !ok {
			continue
		}
		res := classifier.ClassifyRoom(obs, classifyOpts)
		if res.Category != classifier.CategorySingleUserNote {
			continue
		}

		if res.Local != nil && res.Local.Encryption != nil {
			stateStore.Encryption[roomID] = &event.EncryptionEventContent{
				Algorithm:              id.Algorithm(res.Local.Encryption.Algorithm),
				RotationPeriodMillis:   res.Local.Encryption.RotationPeriodMillis,
				RotationPeriodMessages: res.Local.Encryption.RotationPeriodMsgs,
			}
		}

		importRoomBackupSessions(ctx, mach, roomID, backupData, log)

		entries, err := extractRoomNotes(ctx, cli, mach, store, roomID, log)
		if err != nil {
			return fmt.Errorf("extract single-user notes for %s (%s): %w", roomIDStr, acc.UserID, err)
		}
		if len(entries) > 0 {
			notesByRoom[roomIDStr] = entries
		}
	}
	return nil
}

func importRoomBackupSessions(
	ctx context.Context,
	mach *crypto.OlmMachine,
	roomID id.RoomID,
	backupData *extractedBackup,
	log *zerolog.Logger,
) {
	if backupData == nil || backupData.megolmKey == nil {
		return
	}
	roomSessions, ok := backupData.sessionsByRoom[roomID]
	if !ok || len(roomSessions) == 0 {
		return
	}

	sessIDs := make([]id.SessionID, 0, len(roomSessions))
	for sessID := range roomSessions {
		sessIDs = append(sessIDs, sessID)
	}
	slices.Sort(sessIDs)

	for _, sessID := range sessIDs {
		encData := roomSessions[sessID]
		decrypted, decErr := decryptBackupSession(encData, backupData.megolmKey)
		if decErr != nil {
			log.Warn().
				Err(decErr).
				Str("room_id", roomID.String()).
				Str("session_id", sessID.String()).
				Msg("Failed to decrypt room backup session for single-user notes")
			continue
		}
		if _, impErr := mach.ImportRoomKeyFromBackup(ctx, id.KeyBackupVersion(backupData.version), roomID, sessID, decrypted); impErr != nil {
			log.Warn().
				Err(impErr).
				Str("room_id", roomID.String()).
				Str("session_id", sessID.String()).
				Msg("Failed to import Megolm session into OlmMachine for single-user notes")
		}
	}
}

func extractRoomNotes(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	store *dump.Store,
	roomID id.RoomID,
	log *zerolog.Logger,
) ([]dump.NoteEntry, error) {
	timeline, err := fetchRoomTimelineChronological(ctx, cli, roomID)
	if err != nil {
		return nil, err
	}

	state := noteExtractionState{
		edits:        make(map[string]*event.MessageEventContent),
		reactions:    make(map[string][]string),
		reactionSeen: make(map[string]map[string]struct{}),
		entries:      make([]dump.NoteEntry, 0, len(timeline)),
	}

	for _, evt := range timeline {
		if procErr := processTimelineEvent(ctx, cli, mach, store, roomID, evt, &state, log); procErr != nil {
			return nil, procErr
		}
	}

	if editErr := applyNoteEdits(ctx, cli, store, roomID, &state, log); editErr != nil {
		return nil, editErr
	}

	for i := range state.entries {
		if reacts, ok := state.reactions[state.entries[i].EventID]; ok {
			state.entries[i].Reactions = reacts
		}
	}

	return state.entries, nil
}

func fetchRoomTimelineChronological(ctx context.Context, cli *mautrix.Client, roomID id.RoomID) ([]*event.Event, error) {
	var timeline []*event.Event
	fromToken := ""

	for {
		resp, err := cli.Messages(ctx, roomID, fromToken, "", mautrix.DirectionBackward, nil, messagesPageLimit)
		if err != nil {
			return nil, fmt.Errorf("paginate room messages: %w", err)
		}
		if resp == nil || len(resp.Chunk) == 0 {
			break
		}
		timeline = append(timeline, resp.Chunk...)
		if resp.End == "" || resp.End == fromToken {
			break
		}
		fromToken = resp.End
	}

	slices.Reverse(timeline)
	return timeline, nil
}

func processTimelineEvent(
	ctx context.Context,
	cli *mautrix.Client,
	mach *crypto.OlmMachine,
	store *dump.Store,
	roomID id.RoomID,
	evt *event.Event,
	state *noteExtractionState,
	log *zerolog.Logger,
) error {
	if evt == nil || evt.StateKey != nil || evt.Unsigned.RedactedBecause != nil {
		return nil
	}
	if evt.RoomID == "" {
		evt.RoomID = roomID
	}

	if parseErr := evt.Content.ParseRaw(evt.Type); parseErr != nil && !errors.Is(parseErr, event.ErrUnsupportedContentType) {
		log.Warn().
			Err(parseErr).
			Str("room_id", roomID.String()).
			Str("event_id", evt.ID.String()).
			Str("event_type", evt.Type.Type).
			Msg("Skipping timeline event with unparseable content in single-user notes")
		return nil
	}

	if evt.Type == event.EventEncrypted {
		decrypted, ok := decryptTimelineEvent(ctx, mach, roomID, evt, log)
		if !ok {
			return nil
		}
		evt = decrypted
	}

	switch evt.Type {
	case event.EventReaction:
		recordReaction(evt, state)
		return nil
	case event.EventMessage:
		return recordMessageEvent(ctx, cli, store, evt, state, log)
	default:
		return nil
	}
}

func decryptTimelineEvent(
	ctx context.Context,
	mach *crypto.OlmMachine,
	roomID id.RoomID,
	evt *event.Event,
	log *zerolog.Logger,
) (*event.Event, bool) {
	decrypted, err := mach.DecryptMegolmEvent(ctx, evt)
	if err != nil {
		sessionID := ""
		if enc := evt.Content.AsEncrypted(); enc != nil {
			sessionID = enc.SessionID.String()
		}
		log.Warn().
			Err(err).
			Str("room_id", roomID.String()).
			Str("event_id", evt.ID.String()).
			Str("session_id", sessionID).
			Msg("Skipping undecryptable Megolm event in single-user notes")
		return nil, false
	}
	return decrypted, true
}

func recordReaction(evt *event.Event, state *noteExtractionState) {
	react := evt.Content.AsReaction()
	targetID := react.RelatesTo.GetAnnotationID().String()
	key := react.RelatesTo.GetAnnotationKey()
	if targetID == "" || key == "" {
		return
	}
	seen := state.reactionSeen[targetID]
	if seen == nil {
		seen = make(map[string]struct{})
		state.reactionSeen[targetID] = seen
	}
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	state.reactions[targetID] = append(state.reactions[targetID], key)
}

func recordMessageEvent(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	evt *event.Event,
	state *noteExtractionState,
	log *zerolog.Logger,
) error {
	msg := evt.Content.AsMessage()
	if msg.RelatesTo != nil && msg.RelatesTo.Type == event.RelReplace {
		targetID := msg.RelatesTo.GetReplaceID().String()
		if targetID != "" {
			replacement := msg.NewContent
			if replacement == nil {
				replacement = msg
			}
			state.edits[targetID] = replacement
		}
		return nil
	}

	requiresMedia := msg.MsgType.IsMedia() || msg.File != nil || msg.URL != ""
	mediaRef, foundMedia, mediaErr := exportNoteMedia(ctx, cli, store, msg, evt.ID, log)
	if mediaErr != nil {
		return mediaErr
	}
	if requiresMedia && !foundMedia {
		log.Warn().
			Str("room_id", evt.RoomID.String()).
			Str("event_id", evt.ID.String()).
			Str("msgtype", string(msg.MsgType)).
			Msg("Skipping note message because its media attachment could not be exported")
		return nil
	}
	var mediaPtr *dump.MediaRef
	if foundMedia {
		mediaPtr = &mediaRef
	}

	rawInfo, infoErr := encodeCleanFileInfo(msg.Info)
	if infoErr != nil {
		return infoErr
	}

	state.entries = append(state.entries, dump.NoteEntry{
		EventID:        evt.ID.String(),
		MsgType:        string(msg.MsgType),
		Body:           msg.Body,
		Format:         string(msg.Format),
		FormattedBody:  msg.FormattedBody,
		ReplyToEventID: extractReplyTarget(msg),
		Media:          mediaPtr,
		Info:           rawInfo,
		Timestamp:      evt.Timestamp,
	})
	return nil
}

func applyNoteEdits(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	roomID id.RoomID,
	state *noteExtractionState,
	log *zerolog.Logger,
) error {
	kept := make([]dump.NoteEntry, 0, len(state.entries))
	for i := range state.entries {
		entry := state.entries[i]
		editContent, hasEdit := state.edits[entry.EventID]
		if hasEdit && editContent != nil {
			keep, err := applySingleNoteEdit(ctx, cli, store, roomID, &entry, editContent, log)
			if err != nil {
				return err
			}
			if !keep {
				continue
			}
		}
		kept = append(kept, entry)
	}
	state.entries = kept
	return nil
}

func applySingleNoteEdit(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	roomID id.RoomID,
	entry *dump.NoteEntry,
	editContent *event.MessageEventContent,
	log *zerolog.Logger,
) (keep bool, err error) {
	if editContent.MsgType != "" {
		entry.MsgType = string(editContent.MsgType)
	}
	entry.Body = editContent.Body
	entry.Format = string(editContent.Format)
	entry.FormattedBody = editContent.FormattedBody
	if editContent.File != nil || editContent.URL != "" {
		mediaRef, foundMedia, mediaErr := exportNoteMedia(ctx, cli, store, editContent, id.EventID(entry.EventID), log)
		if mediaErr != nil {
			return false, mediaErr
		}
		if !foundMedia {
			log.Warn().
				Str("room_id", roomID.String()).
				Str("event_id", entry.EventID).
				Str("msgtype", entry.MsgType).
				Msg("Skipping edited note message because its media attachment could not be exported")
			return false, nil
		}
		entry.Media = &mediaRef
	}
	if editContent.Info != nil {
		rawInfo, infoErr := encodeCleanFileInfo(editContent.Info)
		if infoErr != nil {
			return false, infoErr
		}
		entry.Info = rawInfo
	}
	if event.MessageType(entry.MsgType).IsMedia() && entry.Media == nil {
		log.Warn().
			Str("room_id", roomID.String()).
			Str("event_id", entry.EventID).
			Str("msgtype", entry.MsgType).
			Msg("Skipping edited note message with missing media attachment")
		return false, nil
	}
	return true, nil
}

func extractReplyTarget(msg *event.MessageEventContent) string {
	if msg.RelatesTo == nil {
		return ""
	}
	if nonFallback := msg.RelatesTo.GetNonFallbackReplyTo(); nonFallback != "" {
		return nonFallback.String()
	}
	if replyID := msg.RelatesTo.GetReplyTo(); replyID != "" {
		return replyID.String()
	}
	return ""
}

func exportNoteMedia(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	msg *event.MessageEventContent,
	eventID id.EventID,
	log *zerolog.Logger,
) (dump.MediaRef, bool, error) {
	fallbackMime := ""
	if msg.Info != nil {
		fallbackMime = msg.Info.MimeType
	}
	fileName := msg.GetFileName()

	if msg.File != nil {
		return exportEncryptedNoteMedia(ctx, cli, store, msg.File, fallbackMime, fileName, eventID, log)
	}
	if msg.URL == "" {
		return dump.MediaRef{}, false, nil
	}
	parsedURI, parseErr := msg.URL.Parse()
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("event_id", eventID.String()).Msg("Skipping note attachment with invalid MXC URI")
		return dump.MediaRef{}, false, nil
	}
	return downloadOptionalMedia(ctx, cli, store, parsedURI, fallbackMime, fileName, log)
}

func exportEncryptedNoteMedia(
	ctx context.Context,
	cli *mautrix.Client,
	store *dump.Store,
	encFile *event.EncryptedFileInfo,
	fallbackMime string,
	fileName string,
	eventID id.EventID,
	log *zerolog.Logger,
) (dump.MediaRef, bool, error) {
	parsedURI, parseErr := encFile.URL.Parse()
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("event_id", eventID.String()).Msg("Skipping encrypted note attachment with invalid MXC URI")
		return dump.MediaRef{}, false, nil
	}
	cipherBytes, contentType, dlErr := matrix.DownloadMediaWithFallback(ctx, cli, parsedURI)
	if dlErr != nil {
		if isNotFoundErr(dlErr) {
			log.Warn().Str("event_id", eventID.String()).Str("mxc", parsedURI.String()).Msg("Encrypted note media returned 404 on Synapse; skipping attachment")
			return dump.MediaRef{}, false, nil
		}
		return dump.MediaRef{}, false, fmt.Errorf("download encrypted note media %s: %w", parsedURI.String(), dlErr)
	}
	if decErr := encFile.DecryptInPlace(cipherBytes); decErr != nil {
		log.Warn().Err(decErr).Str("event_id", eventID.String()).Str("mxc", parsedURI.String()).Msg("Failed to decrypt note attachment; skipping attachment")
		return dump.MediaRef{}, false, nil
	}
	if fallbackMime != "" {
		contentType = fallbackMime
	}
	ref, saveErr := store.SaveMedia(parsedURI.String(), contentType, fileName, cipherBytes)
	if saveErr != nil {
		return dump.MediaRef{}, false, fmt.Errorf("save decrypted note media %s: %w", parsedURI.String(), saveErr)
	}
	return *ref, true, nil
}

func encodeCleanFileInfo(info *event.FileInfo) (json.RawMessage, error) {
	if info == nil {
		return nil, nil
	}
	cleaned := event.FileInfo{
		MimeType:     info.MimeType,
		Blurhash:     info.Blurhash,
		AnoaBlurhash: info.AnoaBlurhash,
		IsAnimated:   info.IsAnimated,
		Width:        info.Width,
		Height:       info.Height,
		Duration:     info.Duration,
		Size:         info.Size,
		Extra:        maps.Clone(info.Extra),
	}
	if cleaned.IsZero() && len(cleaned.Extra) == 0 {
		return nil, nil
	}
	encoded, err := jsonMarshal(&cleaned)
	if err != nil {
		return nil, fmt.Errorf("encode note file info: %w", err)
	}
	return encoded, nil
}
