package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
)

const defaultBinaryMimeType = "application/octet-stream"

var newInboundGroupSession = olm.NewInboundGroupSession

func replayRoomNotes(
	ctx context.Context,
	store *dump.Store,
	acc *importedAccount,
	newRoomID id.RoomID,
	room *dump.LocalRoom,
	log *zerolog.Logger,
) error {
	isEncrypted := room.Encryption != nil && room.Encryption.Algorithm != ""
	if isEncrypted && (acc.backupKey == nil || acc.backupVersion == "") {
		log.Warn().
			Str("user_id", acc.userID).
			Str("room_id", newRoomID.String()).
			Msg("Encrypted single-user notes room has no online key backup; skipping notes replay")
		return nil
	}

	if isEncrypted {
		if err := initAndBackupNotesMegolmSession(ctx, acc, newRoomID, room); err != nil {
			return err
		}
	}

	eventIDMap := make(map[string]id.EventID, len(room.Notes))
	replayedCount := 0
	for i := range room.Notes {
		note := &room.Notes[i]
		if event.MessageType(note.MsgType).IsMedia() && (note.Media == nil || note.Media.SHA256 == "") {
			log.Warn().
				Str("user_id", acc.userID).
				Str("room_id", newRoomID.String()).
				Str("event_id", note.EventID).
				Str("msgtype", note.MsgType).
				Msg("Skipping note message with missing media attachment")
			continue
		}
		if err := replaySingleNote(ctx, store, acc, newRoomID, room, isEncrypted, note, eventIDMap); err != nil {
			return fmt.Errorf("note %s: %w", note.EventID, err)
		}
		replayedCount++
	}

	log.Info().
		Str("user_id", acc.userID).
		Str("room_id", newRoomID.String()).
		Int("notes", replayedCount).
		Bool("encrypted", isEncrypted).
		Msg("Replayed single-user notes into recreated Tuwunel room")
	return nil
}

func initAndBackupNotesMegolmSession(
	ctx context.Context,
	acc *importedAccount,
	newRoomID id.RoomID,
	room *dump.LocalRoom,
) error {
	acc.stateStore.Encryption[newRoomID] = &event.EncryptionEventContent{
		Algorithm:              id.Algorithm(room.Encryption.Algorithm),
		RotationPeriodMillis:   room.Encryption.RotationPeriodMillis,
		RotationPeriodMessages: room.Encryption.RotationPeriodMsgs,
	}
	if acc.stateStore.HistoryVisibility[newRoomID] == nil {
		hist := defaultHistoryVisibility
		if room.HistoryVisibility != "" {
			hist = event.HistoryVisibility(room.HistoryVisibility)
		}
		acc.stateStore.HistoryVisibility[newRoomID] = &event.HistoryVisibilityEventContent{
			HistoryVisibility: hist,
		}
	}

	if err := acc.mach.ShareGroupSession(ctx, newRoomID, []id.UserID{id.UserID(acc.userID)}); err != nil {
		return fmt.Errorf("share megolm group session: %w", err)
	}

	ogs, err := acc.mach.CryptoStore.GetOutboundGroupSession(ctx, newRoomID)
	if err != nil {
		return fmt.Errorf("load outbound group session: %w", err)
	}
	if ogs == nil {
		return crypto.ErrNoGroupSession
	}

	return uploadOutboundSessionToBackup(ctx, acc, newRoomID, ogs)
}

func uploadOutboundSessionToBackup(
	ctx context.Context,
	acc *importedAccount,
	newRoomID id.RoomID,
	ogs *crypto.OutboundGroupSession,
) error {
	igs, err := newInboundGroupSession([]byte(ogs.Internal.Key()))
	if err != nil {
		return fmt.Errorf("convert outbound megolm key: %w", err)
	}
	exportedKey, err := igs.Export(0)
	if err != nil {
		return fmt.Errorf("export megolm session at index 0: %w", err)
	}

	own := acc.mach.OwnIdentity()
	sessionData := backup.MegolmSessionData{
		Algorithm:          id.AlgorithmMegolmV1,
		ForwardingKeyChain: []string{},
		SenderKey:          own.IdentityKey,
		SessionKey:         string(exportedKey),
		SenderClaimedKeys: backup.SenderClaimedKeys{
			Ed25519: own.SigningKey,
		},
		SharedHistory: ogs.SharedHistory,
	}

	encSession, err := backup.EncryptSessionData(acc.backupKey, sessionData)
	if err != nil {
		return fmt.Errorf("encrypt megolm session for backup: %w", err)
	}
	encodedSession, err := jsonMarshal(encSession)
	if err != nil {
		return fmt.Errorf("encode encrypted backup session: %w", err)
	}

	_, err = acc.cli.PutKeysInBackupForRoomAndSession(
		ctx,
		id.KeyBackupVersion(acc.backupVersion),
		newRoomID,
		ogs.ID(),
		&mautrix.ReqKeyBackupData{
			FirstMessageIndex: 0,
			ForwardedCount:    0,
			IsVerified:        true,
			SessionData:       encodedSession,
		},
	)
	if err != nil {
		return fmt.Errorf("upload replayed notes megolm session %s to backup: %w", ogs.ID(), err)
	}
	return nil
}

func replaySingleNote(
	ctx context.Context,
	store *dump.Store,
	acc *importedAccount,
	newRoomID id.RoomID,
	room *dump.LocalRoom,
	isEncrypted bool,
	note *dump.NoteEntry,
	eventIDMap map[string]id.EventID,
) error {
	msgContent, err := buildNoteMessageContent(ctx, store, acc.cli, isEncrypted, note, eventIDMap)
	if err != nil {
		return err
	}

	var sendResp *mautrix.RespSendEvent
	if isEncrypted {
		encContent, encErr := encryptNoteEvent(ctx, acc, newRoomID, room, msgContent)
		if encErr != nil {
			return encErr
		}
		sendResp, err = acc.cli.SendMessageEvent(ctx, newRoomID, event.EventEncrypted, encContent, mautrix.ReqSendEvent{
			DontEncrypt: true,
		})
	} else {
		sendResp, err = acc.cli.SendMessageEvent(ctx, newRoomID, event.EventMessage, msgContent)
	}
	if err != nil {
		return fmt.Errorf("send note message: %w", err)
	}

	if note.EventID != "" {
		eventIDMap[note.EventID] = sendResp.EventID
	}

	for _, key := range note.Reactions {
		if key == "" {
			continue
		}
		reactContent := &event.ReactionEventContent{}
		reactContent.RelatesTo.SetAnnotation(sendResp.EventID, key)
		if _, err := acc.cli.SendMessageEvent(ctx, newRoomID, event.EventReaction, reactContent); err != nil {
			return fmt.Errorf("send reaction %q: %w", key, err)
		}
	}
	return nil
}

func encryptNoteEvent(
	ctx context.Context,
	acc *importedAccount,
	newRoomID id.RoomID,
	room *dump.LocalRoom,
	msgContent *event.MessageEventContent,
) (*event.EncryptedEventContent, error) {
	encContent, encErr := acc.mach.EncryptMegolmEvent(ctx, newRoomID, event.EventMessage, msgContent)
	if encErr == nil {
		return encContent, nil
	}
	if !errors.Is(encErr, crypto.ErrSessionExpired) {
		return nil, fmt.Errorf("encrypt note event: %w", encErr)
	}
	if rotErr := initAndBackupNotesMegolmSession(ctx, acc, newRoomID, room); rotErr != nil {
		return nil, fmt.Errorf("rotate expired notes megolm session: %w", rotErr)
	}
	encContent, encErr = acc.mach.EncryptMegolmEvent(ctx, newRoomID, event.EventMessage, msgContent)
	if encErr != nil {
		return nil, fmt.Errorf("encrypt note event after session rotation: %w", encErr)
	}
	return encContent, nil
}

func buildNoteMessageContent(
	ctx context.Context,
	store *dump.Store,
	cli *mautrix.Client,
	isEncrypted bool,
	note *dump.NoteEntry,
	eventIDMap map[string]id.EventID,
) (*event.MessageEventContent, error) {
	msgType := event.MessageType(note.MsgType)
	if msgType == "" {
		msgType = event.MsgText
	}

	msg := &event.MessageEventContent{
		MsgType:       msgType,
		Body:          note.Body,
		Format:        event.Format(note.Format),
		FormattedBody: note.FormattedBody,
	}

	if len(note.Info) > 0 {
		var fileInfo event.FileInfo
		if err := json.Unmarshal(note.Info, &fileInfo); err != nil {
			return nil, fmt.Errorf("unmarshal note file info: %w", err)
		}
		msg.Info = &fileInfo
	}

	if note.ReplyToEventID != "" {
		if targetID, ok := eventIDMap[note.ReplyToEventID]; ok {
			msg.RelatesTo = (&event.RelatesTo{}).SetReplyTo(targetID)
		}
	}

	if note.Media != nil && note.Media.SHA256 != "" {
		if err := attachNoteMedia(ctx, store, cli, isEncrypted, note.Media, msg); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

func attachNoteMedia(
	ctx context.Context,
	store *dump.Store,
	cli *mautrix.Client,
	isEncrypted bool,
	media *dump.MediaRef,
	msg *event.MessageEventContent,
) error {
	rawBytes, err := store.ReadMedia(media.SHA256)
	if err != nil {
		return fmt.Errorf("read note media %s: %w", media.SHA256, err)
	}
	msg.FileName = media.FileName

	if isEncrypted {
		payload := bytes.Clone(rawBytes)
		encFile := attachment.NewEncryptedFile()
		encFile.EncryptInPlace(payload)
		upResp, upErr := cli.UploadBytesWithName(ctx, payload, defaultBinaryMimeType, "")
		if upErr != nil {
			return fmt.Errorf("upload encrypted note media: %w", upErr)
		}
		msg.File = &event.EncryptedFileInfo{
			EncryptedFile: *encFile,
			URL:           id.ContentURIString(upResp.ContentURI.String()),
		}
		return nil
	}

	ct := media.ContentType
	if ct == "" {
		ct = defaultBinaryMimeType
	}
	upResp, err := cli.UploadBytesWithName(ctx, rawBytes, ct, media.FileName)
	if err != nil {
		return fmt.Errorf("upload note media: %w", err)
	}
	msg.URL = id.ContentURIString(upResp.ContentURI.String())
	return nil
}
