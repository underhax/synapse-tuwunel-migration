package importer

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix"
)

type ogsOverrideCryptoStore struct {
	crypto.Store
	err        error
	failAfter  int
	failOnCall int
	calls      int
}

func (s *ogsOverrideCryptoStore) GetOutboundGroupSession(ctx context.Context, roomID id.RoomID) (*crypto.OutboundGroupSession, error) {
	s.calls++
	if s.failOnCall > 0 {
		if s.calls == s.failOnCall {
			return nil, s.err
		}
	} else if s.calls > s.failAfter {
		return nil, s.err
	}
	res, err := s.Store.GetOutboundGroupSession(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("delegate GetOutboundGroupSession: %w", err)
	}
	return res, nil
}

type failingExportInboundSession struct {
	olm.InboundGroupSession
}

func (failingExportInboundSession) Export(_ uint32) ([]byte, error) {
	return nil, errors.New("mock export failure")
}

func failingNewInboundGroupSession(_ []byte) (olm.InboundGroupSession, error) {
	return nil, errors.New("mock new inbound group session failure")
}

func failingExportNewInboundGroupSession(sessionKey []byte) (olm.InboundGroupSession, error) {
	realSess, err := olm.NewInboundGroupSession(sessionKey)
	if err != nil {
		return nil, err
	}
	return failingExportInboundSession{InboundGroupSession: realSess}, nil
}

func failingJSONMarshal(_ any) ([]byte, error) {
	return nil, errors.New("mock marshal failure")
}

func setupNotesReplayAccount(t *testing.T, serverName string, withBackup bool) (*dump.Store, *mockTuwunel, *importedAccount, id.RoomID) {
	t.Helper()
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}
	tuw := newMockTuwunel(t, serverName, "sec")
	uid := "@notes:" + serverName
	tuw.addExistingUser(uid, "pw", false)

	cli, _, err := matrix.LoginPassword(context.Background(), tuw.srv.URL, uid, "pw", matrix.DefaultDeviceDisplayName, nil)
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	mach, stateStore, err := matrix.NewOlmMachine(context.Background(), cli, nil)
	if err != nil {
		t.Fatalf("NewOlmMachine: %v", err)
	}
	cli.StateStore = stateStore

	if shareErr := mach.ShareKeys(context.Background(), 0); shareErr != nil {
		t.Fatalf("ShareKeys: %v", shareErr)
	}

	var bk *backup.MegolmBackupKey
	var bver string
	if withBackup {
		var bkErr error
		bk, bkErr = backup.NewMegolmBackupKey()
		if bkErr != nil {
			t.Fatalf("NewMegolmBackupKey: %v", bkErr)
		}
		tuw.mu.Lock()
		tuw.users[uid].BackupVersion = "1"
		tuw.mu.Unlock()
		bver = "1"
	}

	roomResp, err := cli.CreateRoom(context.Background(), &mautrix.ReqCreateRoom{Name: "Notes"})
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	acc := &importedAccount{
		cli:           cli,
		mach:          mach,
		stateStore:    stateStore,
		backupKey:     bk,
		backupVersion: bver,
		userID:        uid,
	}
	return store, tuw, acc, roomResp.RoomID
}

func TestNotesReplayEdgeAndErrorBranches(t *testing.T) {
	log := zerolog.Nop()
	encConfig := &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1)}

	t.Run("missing reply target omitted cleanly", func(t *testing.T) {
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "notes1.example", false)
		room := &dump.LocalRoom{
			Category:      dump.RoomCategoryNotes,
			JoinedMembers: []string{acc.userID},
			Notes: []dump.NoteEntry{
				{EventID: "$n1", Body: "orphan reply", ReplyToEventID: "$nonexistent"},
			},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err != nil {
			t.Fatalf("replayRoomNotes: %v", err)
		}
		tuw.mu.Lock()
		defer tuw.mu.Unlock()
		if len(tuw.rooms[roomID].Timeline) != 1 {
			t.Fatalf("expected 1 note event, got %d", len(tuw.rooms[roomID].Timeline))
		}
	})

	t.Run("encrypted session uses default history visibility", func(t *testing.T) {
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes2.example", true)
		room := &dump.LocalRoom{
			Category:      dump.RoomCategoryNotes,
			JoinedMembers: []string{acc.userID},
			Encryption:    encConfig,
			Notes:         []dump.NoteEntry{{EventID: "$d1", Body: "secret"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err != nil {
			t.Fatalf("replayRoomNotes encrypted: %v", err)
		}
		if acc.stateStore.HistoryVisibility[roomID] == nil || acc.stateStore.HistoryVisibility[roomID].HistoryVisibility != defaultHistoryVisibility {
			t.Fatalf("expected default history visibility stored")
		}
	})

	t.Run("share group session failure via sendToDevice", func(t *testing.T) {
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "notes3.example", true)
		tuw.failRoute(http.MethodPut, "/sendToDevice/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "sendToDevice err")
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$s1", Body: "x"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected ShareGroupSession error")
		}
	})

	t.Run("newInboundGroupSession error", func(t *testing.T) {
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes4.example", true)
		orig := newInboundGroupSession
		defer func() { newInboundGroupSession = orig }()
		newInboundGroupSession = failingNewInboundGroupSession
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$i1", Body: "x"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected newInboundGroupSession error")
		}
	})

	t.Run("export outbound session failure", func(t *testing.T) {
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes5.example", true)
		orig := newInboundGroupSession
		defer func() { newInboundGroupSession = orig }()
		newInboundGroupSession = failingExportNewInboundGroupSession
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$x1", Body: "x"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected Export(0) error")
		}
	})

	t.Run("jsonMarshal encrypted session failure", func(t *testing.T) {
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes6.example", true)
		orig := jsonMarshal
		defer func() { jsonMarshal = orig }()
		jsonMarshal = failingJSONMarshal
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$j1", Body: "x"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected jsonMarshal error")
		}
	})

	t.Run("PutKeysInBackupForRoomAndSession failure", func(t *testing.T) {
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "notes7.example", true)
		tuw.failRoute(http.MethodPut, "/room_keys/keys", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "backup put fail")
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$p1", Body: "x"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected PutKeysInBackupForRoomAndSession error")
		}
	})

	t.Run("missing OGS triggers EncryptMegolmEvent failure", func(t *testing.T) {
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes8.example", true)
		err := replaySingleNote(context.Background(), store, acc, roomID, &dump.LocalRoom{Encryption: encConfig}, true, &dump.NoteEntry{
			EventID: "$o1",
			Body:    "no session",
		}, map[string]id.EventID{})
		if err == nil {
			t.Fatalf("expected EncryptMegolmEvent error without OGS")
		}
	})
}

func TestNotesReplaySessionRotation(t *testing.T) {
	t.Parallel()
	log := zerolog.Nop()

	t.Run("rotates expired megolm session and backs up all sessions", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "rot1.example", true)
		room := &dump.LocalRoom{
			Category:          dump.RoomCategoryNotes,
			JoinedMembers:     []string{acc.userID},
			HistoryVisibility: string(event.HistoryVisibilityJoined),
			Encryption: &dump.EncryptionConfig{
				Algorithm:          string(id.AlgorithmMegolmV1),
				RotationPeriodMsgs: 1,
			},
			Notes: []dump.NoteEntry{
				{EventID: "$rot1", Body: "rotated note 1"},
				{EventID: "$rot2", Body: "rotated note 2", ReplyToEventID: "$rot1"},
				{EventID: "$rot3", Body: "rotated note 3"},
			},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err != nil {
			t.Fatalf("replayRoomNotes rotation: %v", err)
		}

		tuw.mu.Lock()
		sessCount := len(tuw.users[acc.userID].BackupSessions[roomID])
		tuw.mu.Unlock()
		if sessCount != 3 {
			t.Fatalf("expected 3 backed-up megolm sessions after per-message rotation, got %d", sessCount)
		}

		msgs, reacts := decryptReplayedNotesWithKey(t, acc.userID, acc.backupKey, tuw, roomID)
		if len(msgs) != 3 || len(reacts) != 0 {
			t.Fatalf("expected 3 decrypted rotated notes, got msgs=%d reacts=%d", len(msgs), len(reacts))
		}
		wantBodies := []string{"rotated note 1", "rotated note 2", "rotated note 3"}
		for i, want := range wantBodies {
			if msgs[i].Body != want {
				t.Fatalf("note %d body mismatch: got %q want %q", i, msgs[i].Body, want)
			}
		}
	})

	rotFailureCases := []struct {
		name     string
		domain   string
		failHTTP bool
	}{
		{
			name:     "rotation session backup upload failure",
			domain:   "rot2.example",
			failHTTP: true,
		},
		{
			name:   "post-rotation EncryptMegolmEvent store failure",
			domain: "rot3.example",
		},
	}
	for _, tc := range rotFailureCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, tuw, acc, roomID := setupNotesReplayAccount(t, tc.domain, true)
			room := &dump.LocalRoom{
				Encryption: &dump.EncryptionConfig{
					Algorithm:          string(id.AlgorithmMegolmV1),
					RotationPeriodMsgs: 1,
				},
			}
			if err := initAndBackupNotesMegolmSession(context.Background(), acc, roomID, room); err != nil {
				t.Fatalf("initAndBackupNotesMegolmSession: %v", err)
			}
			eventMap := map[string]id.EventID{}
			if err := replaySingleNote(context.Background(), store, acc, roomID, room, true, &dump.NoteEntry{
				EventID: "$pre",
				Body:    "first rotated msg",
			}, eventMap); err != nil {
				t.Fatalf("first replaySingleNote: %v", err)
			}

			if tc.failHTTP {
				tuw.failRoute(http.MethodPut, "/room_keys/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "rotation backup err")
			} else {
				acc.mach.CryptoStore = &ogsOverrideCryptoStore{
					Store:      acc.mach.CryptoStore,
					err:        errors.New("post-rotation db err"),
					failOnCall: 4,
				}
			}

			if err := replaySingleNote(context.Background(), store, acc, roomID, room, true, &dump.NoteEntry{
				EventID: "$post",
				Body:    "second rotated msg",
			}, eventMap); err == nil {
				t.Fatalf("expected rotation error for %s", tc.name)
			}
		})
	}
}

func TestNotesReplaySessionAndVisibilityBranches(t *testing.T) {
	t.Parallel()
	log := zerolog.Nop()
	encConfig := &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1)}

	t.Run("explicit HistoryVisibility applied when stateStore entry absent", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes9.example", true)
		delete(acc.stateStore.HistoryVisibility, roomID)
		room := &dump.LocalRoom{
			Encryption:        encConfig,
			HistoryVisibility: string(event.HistoryVisibilityShared),
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err != nil {
			t.Fatalf("replayRoomNotes explicit history_visibility: %v", err)
		}
		if acc.stateStore.HistoryVisibility[roomID].HistoryVisibility != event.HistoryVisibilityShared {
			t.Fatalf("expected shared history visibility")
		}
	})

	t.Run("GetOutboundGroupSession store error", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes10.example", true)
		acc.mach.CryptoStore = &ogsOverrideCryptoStore{Store: acc.mach.CryptoStore, err: errors.New("ogs db error"), failAfter: 1}
		room := &dump.LocalRoom{Encryption: encConfig}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected GetOutboundGroupSession error")
		}
	})

	t.Run("GetOutboundGroupSession nil returns ErrNoGroupSession", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes11.example", true)
		acc.mach.CryptoStore = &ogsOverrideCryptoStore{Store: acc.mach.CryptoStore}
		room := &dump.LocalRoom{Encryption: encConfig}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); !errors.Is(err, crypto.ErrNoGroupSession) {
			t.Fatalf("expected ErrNoGroupSession, got %v", err)
		}
	})

	t.Run("EncryptSessionData curve mismatch error", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "notes12.example", true)
		p256Key, keyErr := ecdh.P256().GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatalf("GenerateKey P256: %v", keyErr)
		}
		acc.backupKey = &backup.MegolmBackupKey{PrivateKey: p256Key}
		room := &dump.LocalRoom{Encryption: encConfig}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected EncryptSessionData curve mismatch error")
		}
	})
}

func TestNotesReplayMessageAndMediaErrors(t *testing.T) {
	t.Parallel()
	log := zerolog.Nop()
	encConfig := &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1)}

	t.Run("invalid note info JSON", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "m1.example", false)
		room := &dump.LocalRoom{
			Notes: []dump.NoteEntry{{EventID: "$badinfo", Info: json.RawMessage(`{invalid`)}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected note info unmarshal error")
		}
	})

	t.Run("skips media note entries without valid media blob ref", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "notes-skip-media.example", false)
		room := &dump.LocalRoom{
			Category:      dump.RoomCategoryNotes,
			JoinedMembers: []string{acc.userID},
			Notes: []dump.NoteEntry{
				{EventID: "$nomedia", MsgType: string(event.MsgImage), Body: "missing.png"},
				{EventID: "$emptysha", MsgType: string(event.MsgFile), Body: "emptysha.json", Media: &dump.MediaRef{FileName: "emptysha.json"}},
				{EventID: "$oktext", MsgType: string(event.MsgText), Body: "valid text note"},
			},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err != nil {
			t.Fatalf("replayRoomNotes: %v", err)
		}
		tuw.mu.Lock()
		defer tuw.mu.Unlock()
		if len(tuw.rooms[roomID].Timeline) != 1 {
			t.Fatalf("expected 1 replayed note event, got %d", len(tuw.rooms[roomID].Timeline))
		}
	})

	t.Run("missing note media blob", func(t *testing.T) {
		t.Parallel()
		store, _, acc, roomID := setupNotesReplayAccount(t, "m2.example", false)
		room := &dump.LocalRoom{
			Notes: []dump.NoteEntry{{
				EventID: "$nomedia",
				Media:   &dump.MediaRef{SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected ReadMedia error")
		}
	})

	t.Run("encrypted note media upload failure", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "m3.example", true)
		ref, err := store.SaveMedia("mxc://m3.example/1", "image/png", "a.png", []byte("img"))
		if err != nil {
			t.Fatalf("SaveMedia: %v", err)
		}
		tuw.failRoute(http.MethodPost, "/media/v3/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "up fail")
		room := &dump.LocalRoom{
			Encryption: encConfig,
			Notes:      []dump.NoteEntry{{EventID: "$e1", Media: ref}},
		}
		if runErr := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); runErr == nil {
			t.Fatalf("expected encrypted upload error")
		}
	})

	t.Run("plaintext note media upload failure", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "m4.example", false)
		ref, err := store.SaveMedia("mxc://m4.example/2", "", "b.bin", []byte("bin"))
		if err != nil {
			t.Fatalf("SaveMedia: %v", err)
		}
		tuw.failRoute(http.MethodPost, "/media/v3/upload", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "up fail")
		room := &dump.LocalRoom{
			Notes: []dump.NoteEntry{{EventID: "$pt1", Media: ref}},
		}
		if runErr := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); runErr == nil {
			t.Fatalf("expected plaintext upload error")
		}
	})

	t.Run("send note message failure", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "m5.example", false)
		tuw.failRoute(http.MethodPut, "/send/m.room.message/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "send fail")
		room := &dump.LocalRoom{
			Notes: []dump.NoteEntry{{EventID: "$sm1", Body: "hi"}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected send message failure")
		}
	})

	t.Run("send reaction failure", func(t *testing.T) {
		t.Parallel()
		store, tuw, acc, roomID := setupNotesReplayAccount(t, "m6.example", false)
		tuw.failRoute(http.MethodPut, "/send/m.reaction/", http.StatusInternalServerError, mautrix.MUnknown.ErrCode, "react fail")
		room := &dump.LocalRoom{
			Notes: []dump.NoteEntry{{EventID: "$sr1", Body: "hi", Reactions: []string{"🔥"}}},
		}
		if err := replayRoomNotes(context.Background(), store, acc, roomID, room, &log); err == nil {
			t.Fatalf("expected send reaction failure")
		}
	})
}
