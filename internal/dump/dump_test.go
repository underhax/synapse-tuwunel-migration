package dump

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

func TestOpenAndRoot(t *testing.T) {
	base := t.TempDir()
	dumpRoot := filepath.Join(base, "state-dump")

	store, err := Open(dumpRoot)
	if err != nil {
		t.Fatalf("Open(%q) err = %v", dumpRoot, err)
	}
	if store.Root() != dumpRoot {
		t.Errorf("Root() = %q, want %q", store.Root(), dumpRoot)
	}

	subdirs := []string{
		dumpRoot,
		filepath.Join(dumpRoot, roomsDirName),
		filepath.Join(dumpRoot, mediaDirName),
		filepath.Join(dumpRoot, accountsDirName),
	}
	for _, d := range subdirs {
		if dirErr := validator.ValidateDirMode(d, 0o700); dirErr != nil {
			t.Errorf("ValidateDirMode(%q) = %v", d, dirErr)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	base := t.TempDir()
	fileAsDir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		wantErr error
		name    string
		path    string
	}{
		{name: "empty path", path: "   ", wantErr: ErrUnsafePath},
		{name: "dot path", path: ".", wantErr: ErrUnsafePath},
		{name: "file instead of dir", path: fileAsDir, wantErr: validator.ErrNotDirectory},
	}

	for _, tc := range tests {
		_, err := Open(tc.path)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: Open(%q) err = %v, want %v", tc.name, tc.path, err, tc.wantErr)
		}
	}
}

func TestRoundTripGlobalManifestAndRooms(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	manifest := &ManifestState{
		ServerName:             "alpha.example.com",
		LocalRoomVersion:       "12",
		ExportedAt:             "2026-11-09T12:00:00Z",
		Phase:                  PhaseExported,
		ServerSigningKeyID:     "ed25519:a_test",
		ServerSigningPublicKey: "examplePubBase64",
		LocalRoomMap:           map[string]string{"!manifest1:alpha.example.com": "!new1hash"},
		ProvisionedUsers:       map[string]bool{"@alice:alpha.example.com": true},
	}
	if writeErr := store.WriteManifest(manifest); writeErr != nil {
		t.Fatalf("WriteManifest: %v", writeErr)
	}
	gotManifest, err := store.ReadManifest()
	if err != nil || gotManifest.LocalRoomMap["!manifest1:alpha.example.com"] != "!new1hash" || !gotManifest.ProvisionedUsers["@alice:alpha.example.com"] || gotManifest.ServerSigningKeyID != "ed25519:a_test" {
		t.Fatalf("ReadManifest = %+v, err = %v", gotManifest, err)
	}

	maxLife := int64(86400000)
	localRooms := &LocalRoomsData{
		Rooms: []LocalRoom{
			{
				OldRoomID:       "!local1:beta.example.net",
				Category:        RoomCategoryLocal,
				OriginalCreator: "@owner:beta.example.net",
				ChosenCreator:   "@alice:beta.example.net",
				JoinedMembers:   []string{"@alice:beta.example.net", "@bob:beta.example.net"},
				Retention:       &RetentionConfig{MaxLifetime: &maxLife},
				IsDirect:        true,
				Notes: []NoteEntry{
					{
						EventID:        "$ev1",
						MsgType:        "m.text",
						Body:           "Updated note",
						ReplyToEventID: "$ev0",
						Reactions:      []string{"✅"},
						Timestamp:      1700000000,
					},
				},
			},
		},
	}
	if writeErr := store.WriteLocalRooms(localRooms); writeErr != nil {
		t.Fatalf("WriteLocalRooms: %v", writeErr)
	}
	gotLocal, err := store.ReadLocalRooms()
	if err != nil || len(gotLocal.Rooms) != 1 || *gotLocal.Rooms[0].Retention.MaxLifetime != maxLife {
		t.Fatalf("ReadLocalRooms = %+v, err = %v", gotLocal, err)
	}

	fedRooms := &FederatedRoomsData{
		Rooms: []FederatedRoom{
			{
				RoomID:           "!fed1:partner.example.org",
				JoinedLocalUsers: []string{"@carol:gamma.example.org"},
				ViaServers:       []string{"partner.example.org"},
			},
		},
	}
	if writeErr := store.WriteFederatedRooms(fedRooms); writeErr != nil {
		t.Fatalf("WriteFederatedRooms: %v", writeErr)
	}
	gotFed, err := store.ReadFederatedRooms()
	if err != nil || len(gotFed.Rooms) != 1 || gotFed.Rooms[0].ViaServers[0] != "partner.example.org" {
		t.Fatalf("ReadFederatedRooms = %+v, err = %v", gotFed, err)
	}
}

func TestRoundTripAccountArtifacts(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	idUser := "@iduser:alpha.example.com"
	identity := &IdentityData{
		UserID:               idUser,
		DefaultSSSSKeyID:     "key-id-1",
		MasterSeed:           []byte("seed-master"),
		SelfSigningSeed:      []byte("seed-self"),
		UserSigningSeed:      []byte("seed-user"),
		MegolmBackupKey:      []byte("seed-backup"),
		MasterPublicKey:      "pub-master",
		SelfSigningPublicKey: "pub-self",
		UserSigningPublicKey: "pub-user",
		RawSSSSAccountData:   map[string]json.RawMessage{"m.secret_storage.default_key": json.RawMessage(`{"key":"key-id-1"}`)},
	}
	if writeErr := store.WriteIdentity(idUser, identity); writeErr != nil {
		t.Fatalf("WriteIdentity: %v", writeErr)
	}
	gotID, err := store.ReadIdentity(idUser)
	if err != nil || !bytes.Equal(gotID.MasterSeed, []byte("seed-master")) {
		t.Fatalf("ReadIdentity = %+v, err = %v", gotID, err)
	}

	keyUser := "@keyuser:beta.example.net"
	keys := &RoomKeysData{
		UserID: keyUser,
		Rooms: map[string]RoomKeyBackupRoom{
			"!backup1:partner.example.org": {
				Sessions: map[string]RoomKeySession{
					"sess-1": {FirstMessageIndex: 0, IsVerified: true, SessionData: json.RawMessage(`{"ciphertext":"abc"}`)},
				},
			},
		},
	}
	if writeErr := store.WriteRoomKeys(keyUser, keys); writeErr != nil {
		t.Fatalf("WriteRoomKeys: %v", writeErr)
	}
	gotKeys, err := store.ReadRoomKeys(keyUser)
	if err != nil || !gotKeys.Rooms["!backup1:partner.example.org"].Sessions["sess-1"].IsVerified {
		t.Fatalf("ReadRoomKeys = %+v, err = %v", gotKeys, err)
	}

	profUser := "@profuser:gamma.example.org"
	order := 0.5
	profile := &ProfileData{
		UserID:      profUser,
		DisplayName: "Profile Example",
		Direct:      map[string][]string{"@peer:gamma.example.org": {"!dm1:gamma.example.org"}},
		RoomTags:    map[string]map[string]RoomTagEntry{"!dm1:gamma.example.org": {"m.favourite": {Order: &order}}},
	}
	if writeErr := store.WriteProfile(profUser, profile); writeErr != nil {
		t.Fatalf("WriteProfile: %v", writeErr)
	}
	gotProfile, err := store.ReadProfile(profUser)
	if err != nil || gotProfile.DisplayName != "Profile Example" {
		t.Fatalf("ReadProfile = %+v, err = %v", gotProfile, err)
	}
}

func TestRoundTripTrustAndSession(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	trustUser := "@trustuser:delta.example"
	trust := &TrustGraphData{
		UserID:   trustUser,
		Contacts: []TrustedContact{{UserID: "@peer:delta.example", MasterKey: "peer-mk", Local: true}},
	}
	if writeErr := store.WriteTrustGraph(trustUser, trust); writeErr != nil {
		t.Fatalf("WriteTrustGraph: %v", writeErr)
	}
	gotTrust, err := store.ReadTrustGraph(trustUser)
	if err != nil || len(gotTrust.Contacts) != 1 || !gotTrust.Contacts[0].Local {
		t.Fatalf("ReadTrustGraph = %+v, err = %v", gotTrust, err)
	}

	sessUser := "@sessuser:epsilon.example"
	session := &SessionData{
		UserID:        sessUser,
		HomeserverURL: "https://tuwunel.epsilon.example",
		AccessToken:   "example-bearer-session",
		DeviceID:      "MIGRATE01",
	}
	if writeErr := store.WriteSession(sessUser, session); writeErr != nil {
		t.Fatalf("WriteSession: %v", writeErr)
	}
	gotSess, err := store.ReadSession(sessUser)
	if err != nil || gotSess.DeviceID != "MIGRATE01" {
		t.Fatalf("ReadSession = %+v, err = %v", gotSess, err)
	}
	if remErr := store.RemoveSession(sessUser); remErr != nil {
		t.Fatalf("RemoveSession: %v", remErr)
	}
	if _, readErr := store.ReadSession(sessUser); !errors.Is(readErr, os.ErrNotExist) {
		t.Errorf("ReadSession after remove = %v, want os.ErrNotExist", readErr)
	}
}

func TestMediaRoundTripAndErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	payload := []byte("fake-png-payload")
	ref, err := store.SaveMedia("mxc://alpha.example.com/abc", "image/png", "avatar.png", payload)
	if err != nil {
		t.Fatalf("SaveMedia: %v", err)
	}
	if ref.Size != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", ref.Size, len(payload))
	}

	readBack, err := store.ReadMedia(ref.SHA256)
	if err != nil || !bytes.Equal(readBack, payload) {
		t.Fatalf("ReadMedia = %q, err = %v", readBack, err)
	}

	tests := []struct {
		wantErr error
		digest  string
	}{
		{digest: "short", wantErr: ErrInvalidMediaHash},
		{digest: strings.Repeat("Z", 64), wantErr: ErrInvalidMediaHash},
		{digest: strings.Repeat("a", 64), wantErr: os.ErrNotExist},
	}
	for _, tc := range tests {
		if _, readErr := store.ReadMedia(tc.digest); !errors.Is(readErr, tc.wantErr) {
			t.Errorf("ReadMedia(%q) err = %v, want %v", tc.digest, readErr, tc.wantErr)
		}
	}

	origLimit := maxMediaBytes
	t.Cleanup(func() { maxMediaBytes = origLimit })
	maxMediaBytes = 4
	if _, saveErr := store.SaveMedia("mxc://alpha.example.com/big", "text/plain", "big.txt", []byte("12345")); !errors.Is(saveErr, ErrMediaTooLarge) {
		t.Errorf("SaveMedia oversize err = %v, want %v", saveErr, ErrMediaTooLarge)
	}

	maxMediaBytes = origLimit
	origCreate := createTempFile
	t.Cleanup(func() { createTempFile = origCreate })
	sentinel := errors.New("temp fail")
	createTempFile = func(string, string) (*os.File, error) {
		return nil, sentinel
	}
	if _, saveErr := store.SaveMedia("mxc://alpha.example.com/x", "text/plain", "x.txt", []byte("ok")); !errors.Is(saveErr, sentinel) {
		t.Errorf("SaveMedia createTemp error = %v, want %v", saveErr, sentinel)
	}
}

func TestAccountDirValidationErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if remErr := store.RemoveSession("@carol:beta.example.net"); remErr != nil {
		t.Errorf("RemoveSession on missing account dir = %v, want nil", remErr)
	}
	if remErr := store.RemoveSession("not-a-user"); !errors.Is(remErr, validator.ErrInvalidUserID) {
		t.Errorf("RemoveSession invalid user = %v, want ErrInvalidUserID", remErr)
	}
	if wErr := store.WriteIdentity("@foo/bar:beta.example.net", &IdentityData{}); !errors.Is(wErr, ErrUnsafePath) {
		t.Errorf("WriteIdentity slash localpart err = %v, want ErrUnsafePath", wErr)
	}
	if wErr := store.WriteIdentity("bad", &IdentityData{}); !errors.Is(wErr, validator.ErrInvalidUserID) {
		t.Errorf("WriteIdentity bad user err = %v, want ErrInvalidUserID", wErr)
	}

	accountsDir := filepath.Join(store.Root(), accountsDirName)
	badFileAccount := filepath.Join(accountsDir, "@erin:delta.example")
	if wErr := os.WriteFile(badFileAccount, []byte("file"), 0o600); wErr != nil {
		t.Fatalf("write regular file: %v", wErr)
	}
	if wErr := store.WriteIdentity("@erin:delta.example", &IdentityData{}); !errors.Is(wErr, validator.ErrNotDirectory) {
		t.Errorf("WriteIdentity onto file = %v, want ErrNotDirectory", wErr)
	}
	if _, rErr := store.ReadIdentity("@erin:delta.example"); !errors.Is(rErr, validator.ErrNotDirectory) {
		t.Errorf("ReadIdentity onto file = %v, want ErrNotDirectory", rErr)
	}
}

func TestMissingFileReads(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	missingUser := "@dave:gamma.example.org"
	checks := []struct {
		fn   func() error
		name string
	}{
		{name: "ReadManifest", fn: func() error { _, e := store.ReadManifest(); return e }},
		{name: "ReadLocalRooms", fn: func() error { _, e := store.ReadLocalRooms(); return e }},
		{name: "ReadFederatedRooms", fn: func() error { _, e := store.ReadFederatedRooms(); return e }},
		{name: "ReadIdentity", fn: func() error { _, e := store.ReadIdentity(missingUser); return e }},
		{name: "ReadRoomKeys", fn: func() error { _, e := store.ReadRoomKeys(missingUser); return e }},
		{name: "ReadProfile", fn: func() error { _, e := store.ReadProfile(missingUser); return e }},
		{name: "ReadTrustGraph", fn: func() error { _, e := store.ReadTrustGraph(missingUser); return e }},
	}

	for _, tc := range checks {
		if rErr := tc.fn(); !errors.Is(rErr, os.ErrNotExist) {
			t.Errorf("%s missing err = %v, want os.ErrNotExist", tc.name, rErr)
		}
	}

	if _, rErr := store.ReadIdentity("invalid"); !errors.Is(rErr, validator.ErrInvalidUserID) {
		t.Errorf("ReadIdentity invalid user = %v, want ErrInvalidUserID", rErr)
	}
}

func TestJSONErrorPaths(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	badJSONPath := filepath.Join(store.Root(), manifestFileName)
	if wErr := os.WriteFile(badJSONPath, []byte("{bad json"), 0o600); wErr != nil {
		t.Fatalf("write bad json: %v", wErr)
	}
	if _, rErr := store.ReadManifest(); rErr == nil {
		t.Errorf("expected unmarshal error on corrupt manifest")
	}

	origMarshal := jsonMarshal
	t.Cleanup(func() { jsonMarshal = origMarshal })
	marshalSentinel := errors.New("marshal boom")
	jsonMarshal = func(any) ([]byte, error) {
		return nil, marshalSentinel
	}
	if wErr := store.WriteManifest(&ManifestState{}); !errors.Is(wErr, marshalSentinel) {
		t.Errorf("WriteManifest marshal error = %v, want %v", wErr, marshalSentinel)
	}
}

func TestDefaultAtomicHelpers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	if err := writeAtomic(filepath.Join(dir, "missing", "out.json"), []byte("x")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("writeAtomic missing parent dir = %v, want os.ErrNotExist", err)
	}
	if _, err := defaultCreateTemp(filepath.Join(dir, "missing"), ".tmp-*"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("defaultCreateTemp missing dir = %v", err)
	}
	if _, err := defaultReadSecureBytes(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("defaultReadSecureBytes missing = %v", err)
	}
	if err := defaultRenameFile(filepath.Join(dir, "missing"), target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("defaultRenameFile missing = %v", err)
	}

	fileAsDir := filepath.Join(dir, "occupied")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := defaultRemoveFile(filepath.Join(fileAsDir, "sub")); err == nil {
		t.Errorf("defaultRemoveFile non-ENOENT expected error, got nil")
	}
}

func TestDefaultWriteTempAndSyncErrors(t *testing.T) {
	dir := t.TempDir()

	closedTmp, err := os.CreateTemp(dir, ".closed-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	closedPath := closedTmp.Name()
	if closeErr := closedTmp.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}
	if syncErr := defaultWriteTempAndSync(closedTmp, []byte("x")); syncErr == nil {
		t.Errorf("defaultWriteTempAndSync on closed file expected error, got nil")
	}
	if chmodErr := defaultFileChmod(closedTmp, atomicFileMode); chmodErr == nil {
		t.Errorf("defaultFileChmod on closed file expected error, got nil")
	}
	if remErr := defaultRemoveFile(closedPath); remErr != nil {
		t.Fatalf("remove closedPath: %v", remErr)
	}

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	if closeErr := rPipe.Close(); closeErr != nil {
		t.Fatalf("close rPipe: %v", closeErr)
	}
	if syncErr := defaultFileSync(wPipe); syncErr == nil {
		t.Errorf("defaultFileSync on pipe expected error, got nil")
	}
	if closeErr := wPipe.Close(); closeErr != nil {
		t.Fatalf("close wPipe: %v", closeErr)
	}

	origChmod := fileChmod
	t.Cleanup(func() {
		fileChmod = origChmod
	})

	chmodSentinel := errors.New("chmod boom")
	fileChmod = func(*os.File, os.FileMode) error {
		return chmodSentinel
	}
	liveTmp, err := os.CreateTemp(dir, ".live-*")
	if err != nil {
		t.Fatalf("CreateTemp live: %v", err)
	}
	livePath := liveTmp.Name()
	if syncErr := defaultWriteTempAndSync(liveTmp, []byte("x")); !errors.Is(syncErr, chmodSentinel) {
		t.Errorf("defaultWriteTempAndSync chmod err = %v, want %v", syncErr, chmodSentinel)
	}
	if closeErr := liveTmp.Close(); closeErr != nil {
		t.Fatalf("close live: %v", closeErr)
	}
	if remErr := defaultRemoveFile(livePath); remErr != nil {
		t.Fatalf("remove live: %v", remErr)
	}
}

func TestDefaultReadFileBytesErrors(t *testing.T) {
	dir := t.TempDir()
	origReadBytes := readFileBytes
	t.Cleanup(func() {
		readFileBytes = origReadBytes
	})

	if _, rErr := defaultReadFileBytes(filepath.Join(dir, "missing.bin")); !errors.Is(rErr, os.ErrNotExist) {
		t.Errorf("defaultReadFileBytes missing err = %v", rErr)
	}
	secureFile := filepath.Join(dir, "secure.json")
	if wErr := os.WriteFile(secureFile, []byte("x"), 0o600); wErr != nil {
		t.Fatalf("write secure: %v", wErr)
	}
	readSentinel := errors.New("read boom")
	readFileBytes = func(string) ([]byte, error) {
		return nil, readSentinel
	}
	if _, rErr := defaultReadSecureBytes(secureFile); !errors.Is(rErr, readSentinel) {
		t.Errorf("defaultReadSecureBytes err = %v, want %v", rErr, readSentinel)
	}
}

func TestWriteAtomicFailureBranches(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	target := filepath.Join(store.Root(), manifestFileName)

	origWriteSync := writeTempAndSync
	origRename := renameFile
	origRemove := removeFile
	t.Cleanup(func() {
		writeTempAndSync = origWriteSync
		renameFile = origRename
		removeFile = origRemove
	})

	syncSentinel := errors.New("sync failed")
	remSentinel := errors.New("remove failed")

	writeTempAndSync = func(*os.File, []byte) error {
		return syncSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, syncSentinel) {
		t.Errorf("writeAtomic sync failure = %v, want %v", err, syncSentinel)
	}

	writeTempAndSync = func(f *os.File, _ []byte) error {
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}
		return syncSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, syncSentinel) {
		t.Errorf("writeAtomic sync+close failure = %v, want %v", err, syncSentinel)
	}

	writeTempAndSync = func(*os.File, []byte) error {
		return syncSentinel
	}
	removeFile = func(string) error {
		return remSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, remSentinel) {
		t.Errorf("writeAtomic sync+remove failure = %v, want %v", err, remSentinel)
	}

	removeFile = defaultRemoveFile
	writeTempAndSync = func(f *os.File, _ []byte) error {
		return f.Close()
	}
	if err := writeAtomic(target, []byte("x")); err == nil {
		t.Errorf("writeAtomic close error expected non-nil")
	}

	removeFile = func(string) error {
		return remSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, remSentinel) {
		t.Errorf("writeAtomic close+remove error = %v, want %v", err, remSentinel)
	}

	writeTempAndSync = origWriteSync
	removeFile = defaultRemoveFile
	renameSentinel := errors.New("rename failed")
	renameFile = func(string, string) error {
		return renameSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, renameSentinel) {
		t.Errorf("writeAtomic rename error = %v, want %v", err, renameSentinel)
	}

	removeFile = func(string) error {
		return remSentinel
	}
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, remSentinel) {
		t.Errorf("writeAtomic rename+remove error = %v, want %v", err, remSentinel)
	}
}

func TestSigningKeyTOMLOperations(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if vErr := store.ValidateSigningKeyTOML(); !errors.Is(vErr, os.ErrNotExist) {
		t.Fatalf("ValidateSigningKeyTOML before write = %v, want os.ErrNotExist", vErr)
	}

	payload := []byte("[global.admin]\nexecute = ['server shutdown']\n")
	if wErr := store.WriteSigningKeyTOML(payload); wErr != nil {
		t.Fatalf("WriteSigningKeyTOML: %v", wErr)
	}
	if vErr := store.ValidateSigningKeyTOML(); vErr != nil {
		t.Fatalf("ValidateSigningKeyTOML after write: %v", vErr)
	}

	info, statErr := os.Stat(store.SigningKeyTOMLPath())
	if statErr != nil {
		t.Fatalf("Stat TOML: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o400 {
		t.Fatalf("TOML perm = %04o, want 0400", perm)
	}

	updated := []byte("[global.admin]\nexecute = ['query raw put global keypair \\x01']\n")
	if wErr := store.WriteSigningKeyTOML(updated); wErr != nil {
		t.Fatalf("WriteSigningKeyTOML overwrite: %v", wErr)
	}
	readBack, readErr := os.ReadFile(store.SigningKeyTOMLPath())
	if readErr != nil || !bytes.Equal(readBack, updated) {
		t.Fatalf("TOML overwrite readBack = %q, err = %v", readBack, readErr)
	}

	origChmod := fileChmod
	t.Cleanup(func() { fileChmod = origChmod })
	chmodSentinel := errors.New("chmod final fail")
	fileChmod = func(f *os.File, mode os.FileMode) error {
		if mode == readOnlyFileMode {
			return chmodSentinel
		}
		return origChmod(f, mode)
	}
	if wErr := store.WriteSigningKeyTOML(payload); !errors.Is(wErr, chmodSentinel) {
		t.Fatalf("WriteSigningKeyTOML chmod fail = %v, want %v", wErr, chmodSentinel)
	}
}
