package exporter

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/crypto/backup"
	_ "maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type testCryptoBundle struct {
	ssssKey         *ssss.Key
	masterSigner    olm.PKSigning
	selfSigner      olm.PKSigning
	userSigner      olm.PKSigning
	backupKey       *backup.MegolmBackupKey
	accountDataJSON map[string]json.RawMessage
	recoveryKey     string
	defaultKeyID    string
	masterPub       id.Ed25519
	selfPub         id.Ed25519
	userPub         id.Ed25519
	backupPub       id.Ed25519
	senderCurveKey  id.Curve25519
	deviceSigning   id.Ed25519
}

func newTestCryptoBundle(t *testing.T, withBackup bool) *testCryptoBundle {
	t.Helper()

	sk, err := ssss.NewKey("")
	if err != nil {
		t.Fatalf("ssss.NewKey: %v", err)
	}
	masterPK, err := olm.NewPKSigning()
	if err != nil {
		t.Fatalf("NewPKSigning master: %v", err)
	}
	selfPK, err := olm.NewPKSigning()
	if err != nil {
		t.Fatalf("NewPKSigning self: %v", err)
	}
	userPK, err := olm.NewPKSigning()
	if err != nil {
		t.Fatalf("NewPKSigning user: %v", err)
	}
	bk, err := backup.NewMegolmBackupKey()
	if err != nil {
		t.Fatalf("NewMegolmBackupKey: %v", err)
	}

	rawCurve := make([]byte, 32)
	if _, randErr := io.ReadFull(rand.Reader, rawCurve); randErr != nil {
		t.Fatalf("rand sender key: %v", randErr)
	}
	senderCurve := id.Curve25519(base64.RawStdEncoding.EncodeToString(rawCurve))

	rawDevSign := make([]byte, 32)
	if _, randErr := io.ReadFull(rand.Reader, rawDevSign); randErr != nil {
		t.Fatalf("rand device signing: %v", randErr)
	}
	devSign := id.Ed25519(base64.RawStdEncoding.EncodeToString(rawDevSign))

	ad := make(map[string]json.RawMessage)
	ad[event.AccountDataSecretStorageDefaultKey.Type] = mustJSON(t, &ssss.DefaultSecretStorageKeyContent{KeyID: sk.ID})
	ad[event.AccountDataSecretStorageKey.Type+"."+sk.ID] = mustJSON(t, sk.Metadata)
	ad[event.AccountDataCrossSigningMaster.Type] = encryptSSSSRaw(t, sk, event.AccountDataCrossSigningMaster.Type, masterPK.Seed())
	ad[event.AccountDataCrossSigningSelf.Type] = encryptSSSSRaw(t, sk, event.AccountDataCrossSigningSelf.Type, selfPK.Seed())
	ad[event.AccountDataCrossSigningUser.Type] = encryptSSSSRaw(t, sk, event.AccountDataCrossSigningUser.Type, userPK.Seed())
	if withBackup {
		ad[event.AccountDataMegolmBackupKey.Type] = encryptSSSSRaw(t, sk, event.AccountDataMegolmBackupKey.Type, bk.Bytes())
	}

	return &testCryptoBundle{
		ssssKey:         sk,
		recoveryKey:     sk.RecoveryKey(),
		defaultKeyID:    sk.ID,
		masterSigner:    masterPK,
		selfSigner:      selfPK,
		userSigner:      userPK,
		backupKey:       bk,
		masterPub:       masterPK.PublicKey(),
		selfPub:         selfPK.PublicKey(),
		userPub:         userPK.PublicKey(),
		backupPub:       id.Ed25519(base64.RawStdEncoding.EncodeToString(bk.PublicKey().Bytes())),
		senderCurveKey:  senderCurve,
		deviceSigning:   devSign,
		accountDataJSON: ad,
	}
}

func encryptSSSSRaw(t *testing.T, sk *ssss.Key, evtType string, secret []byte) json.RawMessage {
	t.Helper()
	enc := sk.Encrypt(evtType, secret)
	payload := ssss.EncryptedAccountDataEventContent{
		Encrypted: map[string]ssss.EncryptedKeyData{
			sk.ID: enc,
		},
	}
	return mustJSON(t, &payload)
}

func signMasterKeyByOwner(t *testing.T, targetUser id.UserID, targetMaster id.Ed25519, ownerID id.UserID, ownerUserSigner olm.PKSigning) mautrix.CrossSigningKeys {
	t.Helper()
	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, targetMaster.String())
	csk := mautrix.CrossSigningKeys{
		UserID: targetUser,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]id.Ed25519{
			keyID: targetMaster,
		},
	}
	sig, err := ownerUserSigner.SignJSON(&csk)
	if err != nil {
		t.Fatalf("SignJSON: %v", err)
	}
	csk.Signatures = signatures.NewSingleSignature(ownerID, id.KeyAlgorithmEd25519, ownerUserSigner.PublicKey().String(), sig)
	return csk
}

func createTestMegolmSession(
	t *testing.T,
	b *testCryptoBundle,
) (ogs olm.OutboundGroupSession, sessID id.SessionID, encData *backup.EncryptedSessionData[backup.MegolmSessionData]) {
	t.Helper()
	ogs, err := olm.NewOutboundGroupSession()
	if err != nil {
		t.Fatalf("NewOutboundGroupSession: %v", err)
	}
	igs, err := olm.NewInboundGroupSession([]byte(ogs.Key()))
	if err != nil {
		t.Fatalf("NewInboundGroupSession: %v", err)
	}
	exportedKey, err := igs.Export(0)
	if err != nil {
		t.Fatalf("igs.Export: %v", err)
	}

	sessData := backup.MegolmSessionData{
		Algorithm:  id.AlgorithmMegolmV1,
		SenderKey:  b.senderCurveKey,
		SessionKey: string(exportedKey),
		SenderClaimedKeys: backup.SenderClaimedKeys{
			Ed25519: b.deviceSigning,
		},
	}
	encSess, err := backup.EncryptSessionData(b.backupKey, sessData)
	if err != nil {
		t.Fatalf("EncryptSessionData: %v", err)
	}
	return ogs, ogs.ID(), encSess
}

func makeEncryptedMegolmEvent(
	t *testing.T,
	ogs olm.OutboundGroupSession,
	b *testCryptoBundle,
	roomID id.RoomID,
	sender id.UserID,
	eventID id.EventID,
	ts int64,
	innerType event.Type,
	innerContent any,
	relatesTo *event.RelatesTo,
) *event.Event {
	t.Helper()
	plaintextPayload := struct {
		Content any       `json:"content"`
		RoomID  id.RoomID `json:"room_id"`
		Type    string    `json:"type"`
	}{
		RoomID:  roomID,
		Type:    innerType.Type,
		Content: innerContent,
	}
	plainJSON := mustJSON(t, &plaintextPayload)
	ciphertextBytes, err := ogs.Encrypt(plainJSON)
	if err != nil {
		t.Fatalf("ogs.Encrypt: %v", err)
	}
	encContent := event.EncryptedEventContent{
		Algorithm:        id.AlgorithmMegolmV1,
		SenderKey:        b.senderCurveKey,
		SessionID:        ogs.ID(),
		MegolmCiphertext: ciphertextBytes,
		RelatesTo:        relatesTo,
	}
	raw := mustJSON(t, &encContent)
	return &event.Event{
		ID:        eventID,
		RoomID:    roomID,
		Sender:    sender,
		Type:      event.EventEncrypted,
		Timestamp: ts,
		Content: event.Content{
			VeryRaw: raw,
		},
	}
}

func makeEncryptedAttachment(t *testing.T, mxcURI string, plaintext []byte) (info *event.EncryptedFileInfo, cipherBytes []byte) {
	t.Helper()
	buf := append([]byte(nil), plaintext...)
	ef := attachment.NewEncryptedFile()
	ef.EncryptInPlace(buf)
	return &event.EncryptedFileInfo{
		EncryptedFile: *ef,
		URL:           id.ContentURIString(mxcURI),
	}, buf
}

type mockAccountData struct {
	accountData    map[string]json.RawMessage
	accountDataErr map[string]int
	profile        *mautrix.RespUserProfile
	tagsByRoom     map[id.RoomID]map[event.RoomTag]event.TagMetadata
	backupVersion  *mautrix.RespRoomKeysVersion[backup.MegolmAuthData]
	roomKeys       *mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]
	loginErrCode   string
	whoamiOverride id.UserID
	joinedRooms    []id.RoomID
	profileErr     int
	tagErrStatus   int
	backupVerErr   int
	roomKeysErr    int
	loginStatus    int
	logoutCount    int
	profileNull    bool
}

type mockMediaItem struct {
	contentType string
	data        []byte
	statusErr   int
	legacyOnly  bool
}

type mockMessagesPage struct {
	resp      *mautrix.RespMessages
	statusErr int
}

type mockSynapse struct {
	server        *httptest.Server
	accounts      map[id.UserID]*mockAccountData
	tokenUsers    map[string]id.UserID
	passwords     map[id.UserID]string
	masterKeys    map[id.UserID]mautrix.CrossSigningKeys
	selfKeys      map[id.UserID]mautrix.CrossSigningKeys
	userKeys      map[id.UserID]mautrix.CrossSigningKeys
	queryFails    map[string]any
	queryHook     func(req *mautrix.ReqQueryKeys) (*mautrix.RespQueryKeys, int)
	roomStates    map[id.RoomID][]*event.Event
	rawRoomStates map[id.RoomID]json.RawMessage
	roomPages     map[id.RoomID]map[string]mockMessagesPage
	media         map[string]mockMediaItem
	queryErr      int
	roomStateErr  int
	joinedErr     int
	mu            sync.Mutex
}

func newMockSynapse() *mockSynapse {
	ms := &mockSynapse{
		accounts:      make(map[id.UserID]*mockAccountData),
		tokenUsers:    make(map[string]id.UserID),
		passwords:     make(map[id.UserID]string),
		masterKeys:    make(map[id.UserID]mautrix.CrossSigningKeys),
		selfKeys:      make(map[id.UserID]mautrix.CrossSigningKeys),
		userKeys:      make(map[id.UserID]mautrix.CrossSigningKeys),
		queryFails:    make(map[string]any),
		roomStates:    make(map[id.RoomID][]*event.Event),
		rawRoomStates: make(map[id.RoomID]json.RawMessage),
		roomPages:     make(map[id.RoomID]map[string]mockMessagesPage),
		media:         make(map[string]mockMediaItem),
	}
	ms.server = httptest.NewServer(http.HandlerFunc(ms.serveHTTP))
	return ms
}

func (ms *mockSynapse) close() {
	ms.server.Close()
}

func (ms *mockSynapse) registerAccount(userID id.UserID, password, token string, b *testCryptoBundle) *mockAccountData {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	acc := &mockAccountData{
		accountData:    mapsCloneRaw(b.accountDataJSON),
		accountDataErr: make(map[string]int),
		tagsByRoom:     make(map[id.RoomID]map[event.RoomTag]event.TagMetadata),
	}
	ms.accounts[userID] = acc
	ms.passwords[userID] = password
	ms.tokenUsers[token] = userID
	ms.masterKeys[userID] = mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys:   map[id.KeyID]id.Ed25519{id.NewKeyID(id.KeyAlgorithmEd25519, b.masterPub.String()): b.masterPub},
	}
	ms.selfKeys[userID] = mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageSelfSigning},
		Keys:   map[id.KeyID]id.Ed25519{id.NewKeyID(id.KeyAlgorithmEd25519, b.selfPub.String()): b.selfPub},
	}
	ms.userKeys[userID] = mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageUserSigning},
		Keys:   map[id.KeyID]id.Ed25519{id.NewKeyID(id.KeyAlgorithmEd25519, b.userPub.String()): b.userPub},
	}
	return acc
}

func (ms *mockSynapse) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if ms.serveExactRoute(w, r) {
		return
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/_matrix/client/v3/profile/"):
		ms.handleProfile(w, r)
	case strings.HasPrefix(p, "/_matrix/client/v3/user/"):
		ms.handleUserPath(w, r)
	case strings.HasPrefix(p, "/_matrix/client/v3/rooms/"):
		ms.handleRoomsPath(w, r)
	case isMediaPath(p):
		ms.handleMedia(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unknown route")
	}
}

func (ms *mockSynapse) serveExactRoute(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/_matrix/client/v3/login":
		if r.Method == http.MethodPost {
			ms.handleLogin(w, r)
			return true
		}
	case "/_matrix/client/v3/logout":
		if r.Method == http.MethodPost {
			ms.handleLogout(w, r)
			return true
		}
	case "/_matrix/client/v3/account/whoami":
		ms.handleWhoami(w, r)
		return true
	case "/_matrix/client/v3/keys/query":
		ms.handleKeysQuery(w, r)
		return true
	case "/_matrix/client/v3/room_keys/version":
		ms.handleBackupVersion(w, r)
		return true
	case "/_matrix/client/v3/room_keys/keys":
		ms.handleBackupKeys(w, r)
		return true
	case "/_matrix/client/v3/joined_rooms":
		ms.handleJoinedRooms(w, r)
		return true
	}
	return false
}

func isMediaPath(p string) bool {
	return strings.HasPrefix(p, "/_matrix/media/v1/download/") ||
		strings.HasPrefix(p, "/_matrix/media/v3/download/") ||
		strings.HasPrefix(p, "/_matrix/client/v1/media/download/")
}

func (ms *mockSynapse) requireAuthUser(w http.ResponseWriter, r *http.Request) (id.UserID, *mockAccountData, bool) {
	hdr := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(hdr, "Bearer ")
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, mautrix.MUnknownToken.ErrCode, "missing bearer token")
		return "", nil, false
	}
	ms.mu.Lock()
	uid, exists := ms.tokenUsers[token]
	var acc *mockAccountData
	if exists {
		acc = ms.accounts[uid]
	}
	ms.mu.Unlock()
	if !exists || acc == nil {
		writeJSONError(w, http.StatusUnauthorized, mautrix.MUnknownToken.ErrCode, "invalid bearer token")
		return "", nil, false
	}
	return uid, acc, true
}

func (ms *mockSynapse) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqLogin
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, err.Error())
		return
	}
	uid := id.UserID(req.Identifier.User)
	ms.mu.Lock()
	defer ms.mu.Unlock()
	acc, exists := ms.accounts[uid]
	if !exists || ms.passwords[uid] != req.Password {
		writeJSONError(w, http.StatusForbidden, mautrix.MForbidden.ErrCode, "bad password")
		return
	}
	if acc.loginStatus != 0 {
		writeJSONError(w, acc.loginStatus, acc.loginErrCode, "login rejected")
		return
	}
	tok := "login-tok-" + uid.String()
	ms.tokenUsers[tok] = uid
	writeJSONResponse(w, http.StatusOK, &mautrix.RespLogin{
		UserID:      uid,
		AccessToken: tok,
		DeviceID:    "TEMPDEV",
	})
}

func (ms *mockSynapse) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	ms.mu.Lock()
	acc.logoutCount++
	ms.mu.Unlock()
	writeJSONResponse(w, http.StatusOK, &mautrix.RespLogout{})
}

func (ms *mockSynapse) handleWhoami(w http.ResponseWriter, r *http.Request) {
	uid, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	ms.mu.Lock()
	if acc.whoamiOverride != "" {
		uid = acc.whoamiOverride
	}
	ms.mu.Unlock()
	writeJSONResponse(w, http.StatusOK, &mautrix.RespWhoami{
		UserID:   uid,
		DeviceID: "ACCTOKDEV",
	})
}

func (ms *mockSynapse) handleKeysQuery(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqQueryKeys
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, err.Error())
		return
	}
	ms.mu.Lock()
	hook := ms.queryHook
	ms.mu.Unlock()
	if hook != nil {
		if customResp, status := hook(&req); status != 0 {
			if status >= http.StatusBadRequest {
				writeJSONError(w, status, mautrix.MUnknown.ErrCode, "keys query hook error")
				return
			}
			writeJSONResponse(w, status, customResp)
			return
		}
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.queryErr != 0 {
		writeJSONError(w, ms.queryErr, mautrix.MUnknown.ErrCode, "keys query failed")
		return
	}
	resp := mautrix.RespQueryKeys{
		Failures:        ms.queryFails,
		MasterKeys:      make(map[id.UserID]mautrix.CrossSigningKeys),
		SelfSigningKeys: make(map[id.UserID]mautrix.CrossSigningKeys),
		UserSigningKeys: make(map[id.UserID]mautrix.CrossSigningKeys),
	}
	for uid := range req.DeviceKeys {
		if mk, ok := ms.masterKeys[uid]; ok {
			resp.MasterKeys[uid] = mk
		}
		if sk, ok := ms.selfKeys[uid]; ok {
			resp.SelfSigningKeys[uid] = sk
		}
		if uk, ok := ms.userKeys[uid]; ok {
			resp.UserSigningKeys[uid] = uk
		}
	}
	writeJSONResponse(w, http.StatusOK, &resp)
}

func (ms *mockSynapse) handleBackupVersion(w http.ResponseWriter, r *http.Request) {
	_, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	if acc.backupVerErr == http.StatusNotFound || (acc.backupVerErr == 0 && acc.backupVersion == nil) {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "no backup")
		return
	}
	if acc.backupVerErr != 0 {
		writeJSONError(w, acc.backupVerErr, mautrix.MUnknown.ErrCode, "backup ver error")
		return
	}
	writeJSONResponse(w, http.StatusOK, acc.backupVersion)
}

func (ms *mockSynapse) handleBackupKeys(w http.ResponseWriter, r *http.Request) {
	_, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	if acc.roomKeysErr != 0 {
		writeJSONError(w, acc.roomKeysErr, mautrix.MUnknown.ErrCode, "keys error")
		return
	}
	if acc.roomKeys == nil {
		writeJSONResponse(w, http.StatusOK, &mautrix.RespRoomKeys[*backup.EncryptedSessionData[backup.MegolmSessionData]]{
			Rooms: map[id.RoomID]mautrix.RespRoomKeyBackup[*backup.EncryptedSessionData[backup.MegolmSessionData]]{},
		})
		return
	}
	writeJSONResponse(w, http.StatusOK, acc.roomKeys)
}

func (ms *mockSynapse) handleJoinedRooms(w http.ResponseWriter, r *http.Request) {
	_, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	ms.mu.Lock()
	joinedErr := ms.joinedErr
	ms.mu.Unlock()
	if joinedErr != 0 {
		writeJSONError(w, joinedErr, mautrix.MUnknown.ErrCode, "joined rooms error")
		return
	}
	writeJSONResponse(w, http.StatusOK, &mautrix.RespJoinedRooms{JoinedRooms: acc.joinedRooms})
}

func (ms *mockSynapse) handleProfile(w http.ResponseWriter, r *http.Request) {
	targetUser := id.UserID(strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/profile/"))
	ms.mu.Lock()
	acc := ms.accounts[targetUser]
	ms.mu.Unlock()
	if acc == nil || acc.profileErr == http.StatusNotFound || (acc.profileErr == 0 && acc.profile == nil && !acc.profileNull) {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "profile missing")
		return
	}
	if acc.profileErr != 0 {
		writeJSONError(w, acc.profileErr, mautrix.MUnknown.ErrCode, "profile error")
		return
	}
	if acc.profileNull {
		writeRawJSON(w, json.RawMessage("null"))
		return
	}
	writeJSONResponse(w, http.StatusOK, acc.profile)
}

func (ms *mockSynapse) handleUserPath(w http.ResponseWriter, r *http.Request) {
	_, acc, ok := ms.requireAuthUser(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/user/")
	_, tail, found := strings.Cut(rest, "/")
	if !found {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "bad path")
		return
	}

	if adType, isAD := strings.CutPrefix(tail, "account_data/"); isAD {
		if errStatus := acc.accountDataErr[adType]; errStatus != 0 {
			writeJSONError(w, errStatus, mautrix.MUnknown.ErrCode, "account data error")
			return
		}
		raw, exists := acc.accountData[adType]
		if !exists {
			writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "missing account data")
			return
		}
		writeRawJSON(w, raw)
		return
	}

	ms.handleUserRoomTags(w, acc, tail)
}

func (ms *mockSynapse) handleUserRoomTags(w http.ResponseWriter, acc *mockAccountData, tail string) {
	roomSub, isRooms := strings.CutPrefix(tail, "rooms/")
	if !isRooms {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unhandled user route")
		return
	}
	roomIDStr, suffix, okTag := strings.Cut(roomSub, "/tags")
	if !okTag || suffix != "" {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unhandled user route")
		return
	}
	if acc.tagErrStatus != 0 {
		writeJSONError(w, acc.tagErrStatus, mautrix.MUnknown.ErrCode, "tags err")
		return
	}
	tags, hasTags := acc.tagsByRoom[id.RoomID(roomIDStr)]
	if !hasTags {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "no tags")
		return
	}
	writeJSONResponse(w, http.StatusOK, &event.TagEventContent{Tags: tags})
}

func (ms *mockSynapse) handleRoomsPath(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/rooms/")
	roomIDStr, tail, ok := strings.Cut(rest, "/")
	if !ok {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "bad room path")
		return
	}
	roomID := id.RoomID(roomIDStr)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	switch tail {
	case "state":
		if ms.roomStateErr != 0 {
			writeJSONError(w, ms.roomStateErr, mautrix.MUnknown.ErrCode, "state failed")
			return
		}
		if rawState, hasRaw := ms.rawRoomStates[roomID]; hasRaw {
			writeRawJSON(w, rawState)
			return
		}
		writeJSONResponse(w, http.StatusOK, ms.roomStates[roomID])
	case "messages":
		from := r.URL.Query().Get("from")
		page := ms.roomPages[roomID][from]
		if page.statusErr != 0 {
			writeJSONError(w, page.statusErr, mautrix.MUnknown.ErrCode, "messages err")
			return
		}
		if page.resp == nil {
			writeJSONResponse(w, http.StatusOK, &mautrix.RespMessages{})
			return
		}
		writeJSONResponse(w, http.StatusOK, page.resp)
	default:
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unknown room route")
	}
}

func (ms *mockSynapse) handleMedia(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	isLegacy := strings.HasPrefix(p, "/_matrix/media/v3/download/")
	key := p
	for _, prefix := range []string{
		"/_matrix/client/v1/media/download/",
		"/_matrix/media/v1/download/",
		"/_matrix/media/v3/download/",
	} {
		if stripped, ok := strings.CutPrefix(p, prefix); ok {
			key = stripped
			break
		}
	}

	ms.mu.Lock()
	item, ok := ms.media[key]
	ms.mu.Unlock()
	if !ok || (item.legacyOnly && !isLegacy) {
		writeJSONError(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "media not found")
		return
	}
	if item.statusErr != 0 {
		writeJSONError(w, item.statusErr, mautrix.MUnknown.ErrCode, "media err")
		return
	}
	if item.contentType != "" {
		w.Header().Set("Content-Type", item.contentType)
	} else {
		w.Header()["Content-Type"] = nil
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(item.data); err != nil {
		panic(err)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func writeRawJSON(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(raw); err != nil {
		panic(err)
	}
}

func writeJSONResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, errCode, msg string) {
	writeJSONResponse(w, status, &mautrix.RespError{
		ErrCode: errCode,
		Err:     msg,
	})
}

func mapsCloneRaw(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

func makeStateEvt(t *testing.T, evtType event.Type, stateKey string, sender id.UserID, content any) *event.Event {
	t.Helper()
	sk := stateKey
	return &event.Event{
		Type:     evtType,
		StateKey: &sk,
		Sender:   sender,
		Content: event.Content{
			VeryRaw: mustJSON(t, content),
		},
	}
}

func makeCreateEvt(t *testing.T, creator id.UserID) *event.Event {
	t.Helper()
	return makeStateEvt(t, event.StateCreate, "", creator, &event.CreateEventContent{RoomVersion: id.RoomV12})
}

func makeJoinEvt(t *testing.T, userID id.UserID) *event.Event {
	t.Helper()
	return makeStateEvt(t, event.StateMember, userID.String(), userID, &event.MemberEventContent{Membership: event.MembershipJoin})
}
