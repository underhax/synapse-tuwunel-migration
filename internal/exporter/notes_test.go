package exporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/classifier"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
)

type notesFixture struct {
	syn             *mockSynapse
	bundle          *testCryptoBundle
	uid             id.UserID
	notesRoomID     id.RoomID
	secretImgData   []byte
	editedMediaData []byte
}

func setupNotesReplayFixture(t *testing.T) *notesFixture {
	t.Helper()

	syn := newMockSynapse()
	t.Cleanup(syn.close)

	uid := id.UserID("@notes:eta.example.org")
	b := newTestCryptoBundle(t, true)
	acc := syn.registerAccount(uid, "notes-pw", "notes-tok", b)

	ogs, sessID, encSess := createTestMegolmSession(t, b)
	notesRoomID := id.RoomID("!notes1:eta.example.org")
	multiRoomID := id.RoomID("!shared1:eta.example.org")
	peerID := id.UserID("@peer:eta.example.org")
	_ = syn.registerAccount(peerID, "peer-pw", "peer-tok", newTestCryptoBundle(t, false))

	acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
		Version:   "nv1",
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
	}
	acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
		Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			notesRoomID: {
				Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					sessID: {IsVerified: true, SessionData: encSess},
				},
			},
		},
	}
	acc.joinedRooms = []id.RoomID{notesRoomID, multiRoomID}

	syn.roomStates[notesRoomID] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeStateEvt(t, event.StateEncryption, "", uid, &event.EncryptionEventContent{
			Algorithm:              id.AlgorithmMegolmV1,
			RotationPeriodMillis:   604800000,
			RotationPeriodMessages: 100,
		}),
	}
	syn.roomStates[multiRoomID] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeJoinEvt(t, peerID),
	}

	plainFileData := []byte("plaintext-pdf-note-data")
	syn.media["eta.example.org/plainfile"] = mockMediaItem{data: plainFileData, contentType: "application/pdf"}

	secretImgData := []byte("decrypted-png-secret")
	encFileInfo, cipherImgData := makeEncryptedAttachment(t, "mxc://eta.example.org/encimg", secretImgData)
	syn.media["eta.example.org/encimg"] = mockMediaItem{data: cipherImgData, contentType: "application/octet-stream"}

	editedMediaData := []byte("edited-attachment-payload")
	syn.media["eta.example.org/editeddoc"] = mockMediaItem{data: editedMediaData, contentType: "text/markdown"}

	plainNoteEvt := &event.Event{
		ID:        "$doc1",
		Sender:    uid,
		Type:      event.EventMessage,
		Timestamp: 1000,
		Content: event.Content{
			VeryRaw: mustJSON(t, &event.MessageEventContent{
				MsgType:  event.MsgFile,
				Body:     "reference specification",
				FileName: "doc.pdf",
				URL:      "mxc://eta.example.org/plainfile",
				Info: &event.FileInfo{
					MimeType:     "application/pdf",
					Size:         len(plainFileData),
					ThumbnailURL: "mxc://eta.example.org/oldthumb",
				},
			}),
		},
	}

	encOrigEvt := makeEncryptedMegolmEvent(t, ogs, b, notesRoomID, uid, "$enc1", 2000, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgImage,
		Body:    "original photo caption",
		File:    encFileInfo,
		Info:    &event.FileInfo{MimeType: "image/png", Width: 640, Height: 480},
	}, nil)

	encEditEvt := makeEncryptedMegolmEvent(t, ogs, b, notesRoomID, uid, "$edit1", 3000, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "* updated photo caption",
		NewContent: &event.MessageEventContent{
			MsgType:       event.MsgImage,
			Body:          "updated photo caption",
			Format:        event.FormatHTML,
			FormattedBody: "<b>updated photo caption</b>",
			URL:           "mxc://eta.example.org/editeddoc",
			Info:          &event.FileInfo{MimeType: "text/markdown", Size: len(editedMediaData)},
		},
	}, &event.RelatesTo{Type: event.RelReplace, EventID: "$enc1"})

	replyTargetEvt := makeEncryptedMegolmEvent(t, ogs, b, notesRoomID, uid, "$target1", 3500, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "root thought",
	}, nil)

	encReplyEvt := makeEncryptedMegolmEvent(t, ogs, b, notesRoomID, uid, "$reply1", 4000, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "follow-up note",
	}, (&event.RelatesTo{}).SetReplyTo("$target1"))

	reactRelate := (&event.RelatesTo{}).SetAnnotation("$reply1", "✅")
	reactOneEvt := makeEncryptedMegolmEvent(t, ogs, b, notesRoomID, uid, "$react1", 4500, event.EventReaction, &event.ReactionEventContent{
		RelatesTo: *reactRelate,
	}, reactRelate)
	reactDupEvt := &event.Event{
		ID:        "$reactDup",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.EventReaction,
		Timestamp: 4600,
		Content: event.Content{
			VeryRaw: mustJSON(t, &event.ReactionEventContent{
				RelatesTo: *(&event.RelatesTo{}).SetAnnotation("$reply1", "✅"),
			}),
		},
	}
	reactTwoEvt := &event.Event{
		ID:        "$react2",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.EventReaction,
		Timestamp: 4700,
		Content: event.Content{
			VeryRaw: mustJSON(t, &event.ReactionEventContent{
				RelatesTo: *(&event.RelatesTo{}).SetAnnotation("$reply1", "📌"),
			}),
		},
	}

	redactedEvt := &event.Event{
		ID:        "$redacted1",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.EventMessage,
		Timestamp: 4800,
		Unsigned:  event.Unsigned{RedactedBecause: &event.Event{ID: "$redaction"}},
		Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgText, Body: "deleted"})},
	}

	undecryptableEvt := &event.Event{
		ID:        "$lost1",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.EventEncrypted,
		Timestamp: 4900,
		Content: event.Content{
			VeryRaw: mustJSON(t, &event.EncryptedEventContent{
				Algorithm:        id.AlgorithmMegolmV1,
				SenderKey:        b.senderCurveKey,
				SessionID:        "unknownSessionIDOf43CharsLength123456789012",
				MegolmCiphertext: []byte("AwgBEv///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
			}),
		},
	}

	corruptJSONEvt := &event.Event{
		ID:        "$badjson",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.EventMessage,
		Timestamp: 4950,
		Content:   event.Content{Raw: map[string]any{"m.relates_to": "wrong-type"}},
	}

	stateInTimeline := makeStateEvt(t, event.StateRoomName, "", uid, &event.RoomNameEventContent{Name: "Notes"})
	otherEvent := &event.Event{
		ID:        "$custom1",
		RoomID:    notesRoomID,
		Sender:    uid,
		Type:      event.Type{Type: "com.example.custom", Class: event.MessageEventType},
		Timestamp: 5000,
		Content:   event.Content{VeryRaw: json.RawMessage(`{"x":1}`)},
	}

	secondPage := "page-two"
	emptyTailPage := "page-empty-tail"
	syn.roomPages[notesRoomID] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Start: "tok-head",
				End:   secondPage,
				Chunk: []*event.Event{otherEvent, stateInTimeline, corruptJSONEvt, undecryptableEvt, redactedEvt, reactTwoEvt, reactDupEvt, reactOneEvt, encReplyEvt},
			},
		},
		secondPage: {
			resp: &mautrix.RespMessages{
				Start: "tok-p2",
				End:   emptyTailPage,
				Chunk: []*event.Event{replyTargetEvt, encEditEvt, encOrigEvt, plainNoteEvt},
			},
		},
		emptyTailPage: {
			resp: &mautrix.RespMessages{
				Start: "tok-tail",
				End:   "after-tail",
				Chunk: []*event.Event{},
			},
		},
	}

	return &notesFixture{
		syn:             syn,
		bundle:          b,
		uid:             uid,
		notesRoomID:     notesRoomID,
		secretImgData:   secretImgData,
		editedMediaData: editedMediaData,
	}
}

func TestRunWithSingleUserNotesReplayAndRelations(t *testing.T) {
	f := setupNotesReplayFixture(t)

	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	cfg := baseTestConfig("eta.example.org", f.syn.server.URL, store.Root(), config.AccountConfig{
		UserID:          f.uid.String(),
		SynapsePassword: "notes-pw",
		RecoveryKey:     f.bundle.recoveryKey,
	})
	cfg.ReplaySingleUserNotes = true

	var logBuf bytes.Buffer
	log := zerolog.New(&logBuf)
	if runErr := Run(context.Background(), cfg, store, &log); runErr != nil {
		t.Fatalf("Run failed: %v", runErr)
	}

	assertNotesReplayOutputs(t, store, f)
}

type wantNoteExpectation struct {
	eventID       string
	body          string
	formattedBody string
	replyTo       string
	wantMediaSHA  string
	reactions     []string
	wantMedia     bool
}

func assertNotesReplayOutputs(t *testing.T, store *dump.Store, f *notesFixture) {
	t.Helper()

	localRooms, err := store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}

	notesRoom := findLocalRoom(localRooms.Rooms, f.notesRoomID.String())
	if notesRoom == nil || notesRoom.Category != dump.RoomCategoryNotes {
		t.Fatalf("missing notes room in localRooms: %+v", localRooms.Rooms)
	}

	editSum := sha256.Sum256(f.editedMediaData)
	expectedNotes := []wantNoteExpectation{
		{
			eventID:   "$doc1",
			body:      "reference specification",
			wantMedia: true,
		},
		{
			eventID:       "$enc1",
			body:          "updated photo caption",
			formattedBody: "<b>updated photo caption</b>",
			wantMedia:     true,
			wantMediaSHA:  hex.EncodeToString(editSum[:]),
		},
		{
			eventID: "$target1",
			body:    "root thought",
		},
		{
			eventID:   "$reply1",
			body:      "follow-up note",
			replyTo:   "$target1",
			reactions: []string{"✅", "📌"},
		},
	}

	if len(notesRoom.Notes) != len(expectedNotes) {
		t.Fatalf("Notes len = %d, want %d: %+v", len(notesRoom.Notes), len(expectedNotes), notesRoom.Notes)
	}
	for i := range expectedNotes {
		assertNoteEntryMatches(t, i, &notesRoom.Notes[i], &expectedNotes[i])
	}
	if bytes.Contains(notesRoom.Notes[0].Info, []byte("oldthumb")) {
		t.Errorf("thumbnail_url should be stripped from clean Info: %s", notesRoom.Notes[0].Info)
	}

	origSum := sha256.Sum256(f.secretImgData)
	savedOrig, readErr := store.ReadMedia(hex.EncodeToString(origSum[:]))
	if readErr != nil || !bytes.Equal(savedOrig, f.secretImgData) {
		t.Errorf("decrypted original media mismatch: err=%v len=%d", readErr, len(savedOrig))
	}
}

func findLocalRoom(rooms []dump.LocalRoom, roomID string) *dump.LocalRoom {
	for i := range rooms {
		if rooms[i].OldRoomID == roomID {
			return &rooms[i]
		}
	}
	return nil
}

func assertNoteEntryMatches(t *testing.T, idx int, got *dump.NoteEntry, want *wantNoteExpectation) {
	t.Helper()
	if got.EventID != want.eventID || got.Body != want.body || got.FormattedBody != want.formattedBody || got.ReplyToEventID != want.replyTo {
		t.Errorf("Notes[%d] = %+v, want %+v", idx, got, want)
	}
	if !slices.Equal(got.Reactions, want.reactions) {
		t.Errorf("Notes[%d].Reactions = %v, want %v", idx, got.Reactions, want.reactions)
	}
	if want.wantMedia && got.Media == nil {
		t.Errorf("Notes[%d] expected media attachment", idx)
	}
	if want.wantMediaSHA != "" && (got.Media == nil || got.Media.SHA256 != want.wantMediaSHA) {
		t.Errorf("Notes[%d].Media = %+v, want sha=%s", idx, got.Media, want.wantMediaSHA)
	}
}

func TestNoteEdgeCasesAndErrors(t *testing.T) {
	syn := newMockSynapse()
	defer syn.close()

	uid := id.UserID("@notes:theta.example")
	b := newTestCryptoBundle(t, true)
	acc := syn.registerAccount(uid, "pw", "tok", b)
	otherKey := newTestCryptoBundle(t, true)
	_, badSessID, badEncSess := createTestMegolmSession(t, otherKey)

	corruptKeyRoom := id.RoomID("!noteswarn:theta.example")
	acc.backupVersion = &mautrix.RespRoomKeysVersion[backup.MegolmAuthData]{
		Version:   "v1",
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1,
		AuthData:  backup.MegolmAuthData{PublicKey: b.backupPub},
	}
	badImportedSess, err := backup.EncryptSessionData(b.backupKey, backup.MegolmSessionData{
		Algorithm:  id.AlgorithmMegolmV1,
		SenderKey:  b.senderCurveKey,
		SessionKey: "bad-session-key",
	})
	if err != nil {
		t.Fatalf("EncryptSessionData: %v", err)
	}

	edgeOgs, edgeSessID, edgeEncSess := createTestMegolmSession(t, b)
	acc.roomKeys = &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
		Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			"!00valid:theta.example": {Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{edgeSessID: {SessionData: edgeEncSess}}},
			corruptKeyRoom: {
				Sessions: map[id.SessionID]mautrix.RespKeyBackupData[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
					badSessID: {SessionData: badEncSess},
					"badimp":  {SessionData: badImportedSess},
				},
			},
		},
	}

	plainRoom := id.RoomID("!notesedge:theta.example")
	acc.joinedRooms = []id.RoomID{corruptKeyRoom, plainRoom}
	syn.roomStates[corruptKeyRoom] = []*event.Event{
		makeCreateEvt(t, uid),
		makeJoinEvt(t, uid),
		makeStateEvt(t, event.StateEncryption, "", uid, &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}),
	}
	syn.roomStates[plainRoom] = []*event.Event{makeCreateEvt(t, uid), makeJoinEvt(t, uid)}

	syn.roomPages[corruptKeyRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{
					makeEncryptedMegolmEvent(t, edgeOgs, b, corruptKeyRoom, uid, "$otherEnc", 50, event.EventMessage, &event.MessageEventContent{
						MsgType: event.MsgText,
						Body:    "encrypted in warn room",
					}, nil),
				},
			},
		},
	}

	badEncFile, badCipher := makeEncryptedAttachment(t, "mxc://theta.example/badcipher", []byte("orig"))
	badCipher[0] ^= 0xff
	syn.media["theta.example/badcipher"] = mockMediaItem{data: badCipher}

	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{
					{
						ID:        "$fallbackEdit",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 550,
						Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{
							MsgType:   event.MsgText,
							Body:      "edited without new_content",
							RelatesTo: &event.RelatesTo{Type: event.RelReplace, EventID: "$corruptcipher"},
						})},
					},
					{
						ID:        "$emptyreact",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventReaction,
						Timestamp: 500,
						Content:   event.Content{VeryRaw: json.RawMessage(`{}`)},
					},
					{
						ID:        "$badmxc1",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 100,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "bad plain mxc", URL: "invalid-mxc"})},
					},
					{
						ID:        "$badmxc2",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 200,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "bad enc mxc", File: &event.EncryptedFileInfo{URL: "invalid-mxc"}})},
					},
					{
						ID:        "$missing404",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 300,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "missing enc", File: &event.EncryptedFileInfo{URL: "mxc://theta.example/missingenc"}})},
					},
					{
						ID:        "$corruptcipher",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 400,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "corrupt enc", File: badEncFile, Info: &event.FileInfo{MimeType: "application/x-binary"}})},
					},
					{
						ID:        "$emptyimg",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 450,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgImage, Body: "image without url"})},
					},
					{
						ID:        "$validplain",
						RoomID:    plainRoom,
						Sender:    uid,
						Type:      event.EventMessage,
						Timestamp: 600,
						Content:   event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgText, Body: "surviving note"})},
					},
				},
			},
		},
	}

	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	cfg := baseTestConfig("theta.example", syn.server.URL, store.Root(), config.AccountConfig{
		UserID:          uid.String(),
		SynapsePassword: "pw",
		RecoveryKey:     b.recoveryKey,
	})
	cfg.ReplaySingleUserNotes = true

	log := zerolog.Nop()
	if runErr := Run(context.Background(), cfg, store, &log); runErr != nil {
		t.Fatalf("Run warning branches: %v", runErr)
	}
	assertSingleSurvivingNote(t, store, plainRoom.String(), "$validplain")

	syn.roomPages[plainRoom] = map[string]mockMessagesPage{"": {statusErr: http.StatusInternalServerError}}
	if runErr := Run(context.Background(), cfg, store, &log); runErr == nil {
		t.Errorf("expected /messages 500 error")
	}

	syn.media["theta.example/fail500"] = mockMediaItem{statusErr: http.StatusInternalServerError}
	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{{
					ID:      "$enc500",
					RoomID:  plainRoom,
					Sender:  uid,
					Type:    event.EventMessage,
					Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "x", File: &event.EncryptedFileInfo{URL: "mxc://theta.example/fail500"}})},
				}},
			},
		},
	}
	if runErr := Run(context.Background(), cfg, store, &log); runErr == nil {
		t.Errorf("expected encrypted media 500 error")
	}

	hugePayload := make([]byte, dump.MaxMediaBytes+1)
	bigEncFile, bigCipher := makeEncryptedAttachment(t, "mxc://theta.example/bigenc", hugePayload)
	syn.media["theta.example/bigenc"] = mockMediaItem{data: bigCipher}
	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{{
					ID:      "$encbig",
					RoomID:  plainRoom,
					Sender:  uid,
					Type:    event.EventMessage,
					Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "big", File: bigEncFile})},
				}},
			},
		},
	}
	if runErr := Run(context.Background(), cfg, store, &log); runErr == nil {
		t.Errorf("expected oversized note media save failure")
	}

	smallEncFile, smallCipher := makeEncryptedAttachment(t, "mxc://theta.example/smallsave", []byte("small-secret"))
	syn.media["theta.example/smallsave"] = mockMediaItem{data: smallCipher}
	mediaErrStore, err := dump.Open(filepath.Join(t.TempDir(), "media-err-dump"))
	if err != nil {
		t.Fatalf("Open mediaErrStore: %v", err)
	}
	if remErr := os.RemoveAll(filepath.Join(mediaErrStore.Root(), "media")); remErr != nil {
		t.Fatalf("remove mediaErrStore media dir: %v", remErr)
	}
	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{{
					ID:      "$encsavefail",
					RoomID:  plainRoom,
					Sender:  uid,
					Type:    event.EventMessage,
					Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgFile, Body: "small", File: smallEncFile})},
				}},
			},
		},
	}
	if runErr := Run(context.Background(), cfg, mediaErrStore, &log); runErr == nil {
		t.Errorf("expected encrypted note media SaveMedia failure")
	}

	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{
					{
						ID:      "$edit500",
						RoomID:  plainRoom,
						Sender:  uid,
						Type:    event.EventMessage,
						Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgText, Body: "* edit", NewContent: &event.MessageEventContent{MsgType: event.MsgFile, Body: "new", File: &event.EncryptedFileInfo{URL: "mxc://theta.example/fail500"}}, RelatesTo: &event.RelatesTo{Type: event.RelReplace, EventID: "$baseNote"}})},
					},
					{
						ID:      "$baseNote",
						RoomID:  plainRoom,
						Sender:  uid,
						Type:    event.EventMessage,
						Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgText, Body: "orig"})},
					},
				},
			},
		},
	}
	if runErr := Run(context.Background(), cfg, store, &log); runErr == nil {
		t.Errorf("expected edit attachment 500 error")
	}

	syn.roomPages[plainRoom] = map[string]mockMessagesPage{
		"": {
			resp: &mautrix.RespMessages{
				Chunk: []*event.Event{{
					ID:      "$plainOnly",
					RoomID:  plainRoom,
					Sender:  uid,
					Type:    event.EventMessage,
					Content: event.Content{VeryRaw: mustJSON(t, &event.MessageEventContent{MsgType: event.MsgText, Body: "no backup note"})},
				}},
			},
		},
	}
	delete(acc.accountData, event.AccountDataMegolmBackupKey.Type)
	acc.backupVersion = nil
	acc.joinedRooms = []id.RoomID{plainRoom}
	if runErr := Run(context.Background(), cfg, store, &log); runErr != nil {
		t.Errorf("Run plaintext notes without backup = %v", runErr)
	}

	if _, infoErr := encodeCleanFileInfo(&event.FileInfo{ThumbnailURL: "mxc://theta.example/t"}); infoErr != nil {
		t.Errorf("encodeCleanFileInfo empty cleaned = %v", infoErr)
	}

	fallbackReply := &event.RelatesTo{
		Type:          event.RelThread,
		EventID:       "$threadRoot",
		IsFallingBack: true,
		InReplyTo:     &event.InReplyTo{EventID: "$parent"},
	}
	if got := extractReplyTarget(&event.MessageEventContent{RelatesTo: fallbackReply}); got != "$parent" {
		t.Errorf("extractReplyTarget fallback = %q, want $parent", got)
	}
	if got := extractReplyTarget(&event.MessageEventContent{RelatesTo: &event.RelatesTo{Type: event.RelReference, EventID: "$ref1"}}); got != "" {
		t.Errorf("extractReplyTarget non-reply = %q, want empty", got)
	}

	testDirectNoteEdgeBranches(t, store, cfg, uid, plainRoom, &log)
}

func testDirectNoteEdgeBranches(
	t *testing.T,
	store *dump.Store,
	cfg *config.Config,
	uid id.UserID,
	plainRoom id.RoomID,
	log *zerolog.Logger,
) {
	t.Helper()

	if err := exportAccountSingleUserNotes(
		context.Background(),
		nil,
		nil,
		nil,
		store,
		cfg,
		&cfg.Accounts[0],
		map[string]struct{}{},
		&collectedRooms{joinedRoomIDs: []id.RoomID{"!absent:theta.example"}},
		map[string]*classifier.RoomObservation{},
		nil,
		map[string][]dump.NoteEntry{},
		log,
	); err != nil {
		t.Errorf("exportAccountSingleUserNotes missing obs = %v", err)
	}

	state := noteExtractionState{
		edits:        make(map[string]*event.MessageEventContent),
		reactions:    make(map[string][]string),
		reactionSeen: make(map[string]map[string]struct{}),
	}
	if err := processTimelineEvent(context.Background(), nil, nil, store, plainRoom, nil, &state, log); err != nil {
		t.Errorf("processTimelineEvent nil = %v", err)
	}
	recordReaction(&event.Event{Type: event.EventReaction}, &state)
	if err := recordMessageEvent(context.Background(), nil, store, &event.Event{Type: event.EventMessage}, &state, log); err != nil {
		t.Errorf("recordMessageEvent nil parsed = %v", err)
	}

	origMarshal := jsonMarshal
	t.Cleanup(func() { jsonMarshal = origMarshal })
	jsonMarshal = func(any) ([]byte, error) {
		return nil, errors.New("encode info error")
	}
	if _, infoErr := encodeCleanFileInfo(&event.FileInfo{MimeType: "image/jpeg"}); infoErr == nil {
		t.Errorf("expected encodeCleanFileInfo marshal error")
	}

	msgWithInfo := &event.Event{
		ID:      "$infofail",
		RoomID:  plainRoom,
		Sender:  uid,
		Type:    event.EventMessage,
		Content: event.Content{Parsed: &event.MessageEventContent{MsgType: event.MsgText, Body: "b", Info: &event.FileInfo{MimeType: "text/plain"}}},
	}
	if recErr := recordMessageEvent(context.Background(), nil, store, msgWithInfo, &state, log); recErr == nil {
		t.Errorf("expected recordMessageEvent infoErr")
	}

	editState := noteExtractionState{
		edits: map[string]*event.MessageEventContent{
			"$n1": {MsgType: event.MsgText, Body: "edited", Info: &event.FileInfo{MimeType: "text/plain"}},
		},
		entries: []dump.NoteEntry{{EventID: "$n1"}},
	}
	if editErr := applyNoteEdits(context.Background(), nil, store, plainRoom, &editState, log); editErr == nil {
		t.Errorf("expected applyNoteEdits infoErr")
	}
}

func assertSingleSurvivingNote(t *testing.T, store *dump.Store, roomID, wantEventID string) {
	t.Helper()
	localRooms, err := store.ReadLocalRooms()
	if err != nil {
		t.Fatalf("ReadLocalRooms: %v", err)
	}
	room := findLocalRoom(localRooms.Rooms, roomID)
	if room == nil || len(room.Notes) != 1 || room.Notes[0].EventID != wantEventID {
		t.Fatalf("expected only %s to survive broken media filtering, got %+v", wantEventID, room)
	}
}

func TestApplyNoteEditsMediaFiltering(t *testing.T) {
	log := zerolog.Nop()
	roomID := id.RoomID("!edits:theta.example")
	cases := []struct {
		edit      *event.MessageEventContent
		entryID   string
		entryBody string
	}{
		{
			entryID:   "$editBrokenAttachment",
			entryBody: "before broken attachment",
			edit:      &event.MessageEventContent{MsgType: event.MsgImage, Body: "edit 404", File: &event.EncryptedFileInfo{URL: "malformed-edit-mxc"}},
		},
		{
			entryID:   "$editEmptyMediaType",
			entryBody: "before empty media payload",
			edit:      &event.MessageEventContent{MsgType: event.MsgAudio, Body: "edit missing payload"},
		},
		{
			entryID:   "$editValidText",
			entryBody: "before valid edit",
			edit:      &event.MessageEventContent{MsgType: event.MsgText, Body: "after valid edit"},
		},
	}

	edits := make(map[string]*event.MessageEventContent, len(cases))
	entries := make([]dump.NoteEntry, 0, len(cases))
	for _, tc := range cases {
		edits[tc.entryID] = tc.edit
		entries = append(entries, dump.NoteEntry{
			EventID: tc.entryID,
			MsgType: string(event.MsgText),
			Body:    tc.entryBody,
		})
	}
	state := noteExtractionState{
		edits:   edits,
		entries: entries,
	}
	if err := applyNoteEdits(context.Background(), nil, nil, roomID, &state, &log); err != nil {
		t.Fatalf("applyNoteEdits: %v", err)
	}
	if len(state.entries) != 1 || state.entries[0].Body != "after valid edit" {
		t.Fatalf("unexpected surviving edited notes: %+v", state.entries)
	}
}
