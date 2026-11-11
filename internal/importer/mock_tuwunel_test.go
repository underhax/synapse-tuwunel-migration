package importer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	_ "maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix/sharedsecretmac"
)

type mockRegisteredCall struct {
	Username string
	Admin    bool
}

type mockTuwunelUser struct {
	Tokens         map[string]id.DeviceID
	Devices        map[id.DeviceID]mautrix.DeviceKeys
	MasterKey      *mautrix.CrossSigningKeys
	SelfKey        *mautrix.CrossSigningKeys
	UserKey        *mautrix.CrossSigningKeys
	AccountData    map[string]json.RawMessage
	BackupSessions map[id.RoomID]map[id.SessionID]mautrix.ReqKeyBackupData
	RoomTags       map[id.RoomID]map[string]event.TagMetadata
	UserID         string
	Password       string
	DisplayName    string
	AvatarURL      string
	BackupVersion  string
	BackupAuthData json.RawMessage
	Admin          bool
}

type mockUploadedMedia struct {
	ContentType string
	FileName    string
	Data        []byte
}

type mockRecordedEvent struct {
	EventID   id.EventID
	Sender    id.UserID
	EventType string
	Content   json.RawMessage
}

type mockCreatedRoom struct {
	Members       map[id.UserID]bool
	SpaceChildren map[string]event.SpaceChildEventContent
	RoomID        id.RoomID
	Creator       string
	Req           mautrix.ReqCreateRoom
	Timeline      []mockRecordedEvent
}

type mockRouteFailure struct {
	Method      string
	PathSubstr  string
	ErrCode     string
	ErrMsg      string
	StatusCode  int
	TriggerOnce bool
}

type mockTuwunel struct {
	srv               *httptest.Server
	users             map[string]*mockTuwunelUser
	media             map[string]mockUploadedMedia
	rooms             map[id.RoomID]*mockCreatedRoom
	serverName        string
	sharedSecret      string
	nonce             string
	serverKeyID       string
	serverPubB64      string
	registered        []mockRegisteredCall
	loggedOut         []string
	routeFailures     []*mockRouteFailure
	serverPriv        ed25519.PrivateKey
	seq               int
	sendToDevCount    int
	mu                sync.Mutex
	federationEnabled bool
}

func newMockTuwunel(t *testing.T, serverName, sharedSecret string) *mockTuwunel {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read server seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("extract Ed25519 public key")
	}
	m := &mockTuwunel{
		serverName:   serverName,
		sharedSecret: sharedSecret,
		nonce:        "mock-nonce-1",
		serverPriv:   priv,
		serverKeyID:  "ed25519:a_MOCK1",
		serverPubB64: base64.RawStdEncoding.EncodeToString(pub),
		users:        make(map[string]*mockTuwunelUser),
		media:        make(map[string]mockUploadedMedia),
		rooms:        make(map[id.RoomID]*mockCreatedRoom),
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.serveHTTP))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockTuwunel) addExistingUser(userID, password string, admin bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[userID] = &mockTuwunelUser{
		UserID:         userID,
		Password:       password,
		Admin:          admin,
		Tokens:         make(map[string]id.DeviceID),
		Devices:        make(map[id.DeviceID]mautrix.DeviceKeys),
		AccountData:    make(map[string]json.RawMessage),
		BackupSessions: make(map[id.RoomID]map[id.SessionID]mautrix.ReqKeyBackupData),
		RoomTags:       make(map[id.RoomID]map[string]event.TagMetadata),
	}
}

func (m *mockTuwunel) failRoute(method, pathSubstr string, statusCode int, errCode, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeFailures = append(m.routeFailures, &mockRouteFailure{
		Method:     method,
		PathSubstr: pathSubstr,
		StatusCode: statusCode,
		ErrCode:    errCode,
		ErrMsg:     errMsg,
	})
}

func (m *mockTuwunel) checkInjectedFailure(w http.ResponseWriter, r *http.Request) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, rule := range m.routeFailures {
		if rule.Method != "" && rule.Method != r.Method {
			continue
		}
		if strings.Contains(r.URL.Path, rule.PathSubstr) {
			if rule.TriggerOnce {
				m.routeFailures = append(m.routeFailures[:i], m.routeFailures[i+1:]...)
			}
			writeMatrixErr(w, rule.StatusCode, rule.ErrCode, rule.ErrMsg)
			return true
		}
	}
	return false
}

func (m *mockTuwunel) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if m.checkInjectedFailure(w, r) {
		return
	}
	if m.serveAuthAndKeys(w, r) {
		return
	}
	if m.serveRoomsAndMedia(w, r) {
		return
	}
	writeMatrixErr(w, http.StatusNotFound, mautrix.MUnrecognized.ErrCode, "unhandled route: "+r.URL.Path)
}

func (m *mockTuwunel) serveAuthAndKeys(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/_matrix/key/v2/server" && r.Method == http.MethodGet:
		m.handleServerKeys(w, r)
	case r.URL.Path == "/_synapse/admin/v1/register":
		m.handleAdminRegister(w, r)
	case r.URL.Path == "/_matrix/client/v3/login" && r.Method == http.MethodPost:
		m.handleLogin(w, r)
	case r.URL.Path == "/_matrix/client/v3/account/whoami":
		m.handleWhoami(w, r)
	case r.URL.Path == "/_matrix/client/v3/logout" && r.Method == http.MethodPost:
		m.handleLogout(w, r)
	case r.URL.Path == "/_matrix/client/v3/keys/upload":
		m.handleKeysUpload(w, r)
	case r.URL.Path == "/_matrix/client/v3/keys/query":
		m.handleKeysQuery(w, r)
	case r.URL.Path == "/_matrix/client/v3/keys/device_signing/upload":
		m.handleDeviceSigningUpload(w, r)
	case r.URL.Path == "/_matrix/client/v3/keys/signatures/upload":
		m.handleSignaturesUpload(w, r)
	case r.URL.Path == "/_matrix/client/v3/room_keys/version":
		m.handleRoomKeysVersion(w, r)
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/room_keys/keys"):
		m.handleRoomKeysUpload(w, r)
	default:
		return false
	}
	return true
}

func (m *mockTuwunel) serveRoomsAndMedia(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/_matrix/client/v3/createRoom" && r.Method == http.MethodPost:
		m.handleCreateRoom(w, r)
	case r.URL.Path == "/_matrix/media/v3/upload" && r.Method == http.MethodPost:
		m.handleMediaUpload(w, r)
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/sendToDevice/"):
		m.handleSendToDevice(w, r)
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/user/"):
		m.handleUserRoutes(w, r)
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/profile/"):
		m.handleProfileRoutes(w, r)
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/rooms/"):
		m.handleRoomRoutes(w, r)
	default:
		return false
	}
	return true
}

func (m *mockTuwunel) handleServerKeys(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	enabled := m.federationEnabled
	serverName := m.serverName
	keyID := m.serverKeyID
	pubB64 := m.serverPubB64
	priv := m.serverPriv
	m.mu.Unlock()

	if !enabled {
		writeMatrixErr(w, http.StatusForbidden, mautrix.MForbidden.ErrCode, "Federation is disabled")
		return
	}

	payload := map[string]any{
		"server_name":     serverName,
		"valid_until_ts":  int64(1800000000000),
		"verify_keys":     map[string]any{keyID: map[string]string{"key": pubB64}},
		"old_verify_keys": map[string]any{},
	}
	canon, err := canonicaljson.Marshal(payload)
	if err != nil {
		panic(err)
	}
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	payload["signatures"] = map[string]any{
		serverName: map[string]string{keyID: sig},
	}
	writeJSON(w, http.StatusOK, payload)
}

func (m *mockTuwunel) handleAdminRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"nonce": m.nonce})
		return
	}
	var req struct {
		Nonce    string `json:"nonce"`
		Username string `json:"username"`
		Password string `json:"password"`
		Mac      string `json:"mac"`
		Admin    bool   `json:"admin"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	expectedMAC := sharedsecretmac.Compute(m.sharedSecret, req.Nonce, req.Username, req.Password, req.Admin)
	if !hmac.Equal([]byte(expectedMAC), []byte(req.Mac)) {
		writeMatrixErr(w, http.StatusForbidden, mautrix.MForbidden.ErrCode, "invalid hmac")
		return
	}
	uid := "@" + req.Username + ":" + m.serverName
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	devID := id.DeviceID("REGDEV" + strconv.Itoa(m.seq))
	tok := "reg-tok-" + req.Username + "-" + strconv.Itoa(m.seq)
	m.registered = append(m.registered, mockRegisteredCall{Username: req.Username, Admin: req.Admin})
	m.users[uid] = &mockTuwunelUser{
		UserID:         uid,
		Password:       req.Password,
		Admin:          req.Admin,
		Tokens:         map[string]id.DeviceID{tok: devID},
		Devices:        make(map[id.DeviceID]mautrix.DeviceKeys),
		AccountData:    make(map[string]json.RawMessage),
		BackupSessions: make(map[id.RoomID]map[id.SessionID]mautrix.ReqKeyBackupData),
		RoomTags:       make(map[id.RoomID]map[string]event.TagMetadata),
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"home_server":  m.serverName,
		"user_id":      uid,
		"device_id":    devID,
	})
}

func (m *mockTuwunel) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqLogin
	if !decodeBody(w, r, &req) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[req.Identifier.User]
	if !ok || user.Password != req.Password {
		writeMatrixErr(w, http.StatusForbidden, mautrix.MForbidden.ErrCode, "bad password")
		return
	}
	m.seq++
	devID := id.DeviceID("DEV" + strconv.Itoa(m.seq))
	tok := "tok-" + user.UserID + "-" + strconv.Itoa(m.seq)
	user.Tokens[tok] = devID
	writeJSON(w, http.StatusOK, mautrix.RespLogin{
		UserID:      id.UserID(user.UserID),
		AccessToken: tok,
		DeviceID:    devID,
	})
}

func (m *mockTuwunel) authUser(w http.ResponseWriter, r *http.Request) (*mockTuwunelUser, string, id.DeviceID, bool) {
	hdr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if devID, ok := u.Tokens[hdr]; ok {
			return u, hdr, devID, true
		}
	}
	writeMatrixErr(w, http.StatusUnauthorized, mautrix.MUnknownToken.ErrCode, "invalid token")
	return nil, "", "", false
}

func (m *mockTuwunel) handleWhoami(w http.ResponseWriter, r *http.Request) {
	u, _, devID, ok := m.authUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, mautrix.RespWhoami{
		UserID:   id.UserID(u.UserID),
		DeviceID: devID,
	})
}

func (m *mockTuwunel) handleLogout(w http.ResponseWriter, r *http.Request) {
	u, tok, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	m.mu.Lock()
	delete(u.Tokens, tok)
	m.loggedOut = append(m.loggedOut, tok)
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (m *mockTuwunel) handleKeysUpload(w http.ResponseWriter, r *http.Request) {
	u, _, devID, ok := m.authUser(w, r)
	if !ok {
		return
	}
	var req mautrix.ReqUploadKeys
	if !decodeBody(w, r, &req) {
		return
	}
	m.mu.Lock()
	if req.DeviceKeys != nil {
		u.Devices[devID] = *req.DeviceKeys
	}
	otkCount := len(req.OneTimeKeys)
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"one_time_key_counts": map[string]int{"signed_curve25519": otkCount},
	})
}

func (m *mockTuwunel) handleKeysQuery(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := m.authUser(w, r); !ok {
		return
	}
	var req mautrix.ReqQueryKeys
	if !decodeBody(w, r, &req) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	resp := mautrix.RespQueryKeys{
		DeviceKeys:      make(map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys),
		MasterKeys:      make(map[id.UserID]mautrix.CrossSigningKeys),
		SelfSigningKeys: make(map[id.UserID]mautrix.CrossSigningKeys),
		UserSigningKeys: make(map[id.UserID]mautrix.CrossSigningKeys),
	}
	for uid := range req.DeviceKeys {
		u, exists := m.users[uid.String()]
		if !exists {
			continue
		}
		if len(u.Devices) > 0 {
			devs := make(map[id.DeviceID]mautrix.DeviceKeys, len(u.Devices))
			maps.Copy(devs, u.Devices)
			resp.DeviceKeys[uid] = devs
		}
		if u.MasterKey != nil {
			resp.MasterKeys[uid] = *u.MasterKey
		}
		if u.SelfKey != nil {
			resp.SelfSigningKeys[uid] = *u.SelfKey
		}
		if u.UserKey != nil {
			resp.UserSigningKeys[uid] = *u.UserKey
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (m *mockTuwunel) handleDeviceSigningUpload(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	var body struct {
		MasterKey      mautrix.CrossSigningKeys `json:"master_key"`
		SelfSigningKey mautrix.CrossSigningKeys `json:"self_signing_key"`
		UserSigningKey mautrix.CrossSigningKeys `json:"user_signing_key"`
		Auth           struct {
			Type     string `json:"type"`
			Password string `json:"password"`
			Session  string `json:"session"`
		} `json:"auth"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Auth.Type != string(mautrix.AuthTypePassword) || body.Auth.Password != u.Password {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"flows": []map[string]any{
				{"stages": []string{string(mautrix.AuthTypePassword)}},
			},
			"session": "uia-session-1",
		})
		return
	}
	m.mu.Lock()
	mk := body.MasterKey
	sk := body.SelfSigningKey
	uk := body.UserSigningKey
	u.MasterKey = &mk
	u.SelfKey = &sk
	u.UserKey = &uk
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (m *mockTuwunel) handleSignaturesUpload(w http.ResponseWriter, r *http.Request) {
	_, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	var req map[id.UserID]map[string]mautrix.ReqKeysSignatures
	if !decodeBody(w, r, &req) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for targetUID, byKey := range req {
		targetUser, exists := m.users[targetUID.String()]
		if !exists {
			continue
		}
		for keyOrDevID, sigPayload := range byKey {
			if targetUser.MasterKey != nil && targetUser.MasterKey.FirstKey().String() == keyOrDevID {
				mergeSignatures(&targetUser.MasterKey.Signatures, sigPayload.Signatures)
			}
			if dev, hasDev := targetUser.Devices[id.DeviceID(keyOrDevID)]; hasDev {
				mergeSignatures(&dev.Signatures, sigPayload.Signatures)
				targetUser.Devices[id.DeviceID(keyOrDevID)] = dev
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"failures": map[string]any{}})
}

func mergeSignatures(dst *signatures.Signatures, src signatures.Signatures) {
	if *dst == nil {
		*dst = make(signatures.Signatures)
	}
	for signer, keys := range src {
		if (*dst)[signer] == nil {
			(*dst)[signer] = make(map[id.KeyID]string)
		}
		maps.Copy((*dst)[signer], keys)
	}
}

func (m *mockTuwunel) handleRoomKeysVersion(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Method == http.MethodGet {
		if u.BackupVersion == "" {
			writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "no backup version")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"algorithm": id.KeyBackupAlgorithmMegolmBackupV1,
			"auth_data": u.BackupAuthData,
			"version":   u.BackupVersion,
			"count":     0,
			"etag":      "1",
		})
		return
	}
	var req struct {
		Algorithm id.KeyBackupAlgorithm `json:"algorithm"`
		AuthData  json.RawMessage       `json:"auth_data"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	m.seq++
	u.BackupVersion = strconv.Itoa(m.seq)
	u.BackupAuthData = req.AuthData
	writeJSON(w, http.StatusOK, map[string]string{"version": u.BackupVersion})
}

func (m *mockTuwunel) handleRoomKeysUpload(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/room_keys/keys")
	rest = strings.Trim(rest, "/")

	m.mu.Lock()
	defer m.mu.Unlock()
	if u.BackupVersion == "" {
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "backup missing")
		return
	}
	if rest == "" {
		var req mautrix.ReqKeyBackup
		if !decodeBody(w, r, &req) {
			return
		}
		for roomID, roomData := range req.Rooms {
			storeRoomBackup(u, roomID, roomData.Sessions)
		}
	} else {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, "invalid backup path")
			return
		}
		var req mautrix.ReqKeyBackupData
		if !decodeBody(w, r, &req) {
			return
		}
		storeRoomBackup(u, id.RoomID(parts[0]), map[id.SessionID]mautrix.ReqKeyBackupData{
			id.SessionID(parts[1]): req,
		})
	}
	count := 0
	for _, rmap := range u.BackupSessions {
		count += len(rmap)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": count, "etag": "2"})
}

func storeRoomBackup(u *mockTuwunelUser, roomID id.RoomID, sessions map[id.SessionID]mautrix.ReqKeyBackupData) {
	dst, ok := u.BackupSessions[roomID]
	if !ok {
		dst = make(map[id.SessionID]mautrix.ReqKeyBackupData)
		u.BackupSessions[roomID] = dst
	}
	maps.Copy(dst, sessions)
}

func (m *mockTuwunel) handleCreateRoom(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	var req mautrix.ReqCreateRoom
	if !decodeBody(w, r, &req) {
		return
	}
	if errMsg := validateV12Creators(u.UserID, &req); errMsg != "" {
		writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, errMsg)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	roomID := id.RoomID(fmt.Sprintf("!new%d:%s", m.seq, m.serverName))
	m.rooms[roomID] = &mockCreatedRoom{
		RoomID:        roomID,
		Creator:       u.UserID,
		Req:           req,
		Members:       map[id.UserID]bool{id.UserID(u.UserID): true},
		SpaceChildren: make(map[string]event.SpaceChildEventContent),
	}
	writeJSON(w, http.StatusOK, map[string]string{"room_id": roomID.String()})
}

func validateV12Creators(creatorID string, req *mautrix.ReqCreateRoom) string {
	if req.RoomVersion != roomVersionTwelve || req.PowerLevelOverride == nil {
		return ""
	}
	if _, hasCreator := req.PowerLevelOverride.Users[id.UserID(creatorID)]; hasCreator {
		return "v12 creator forbidden in power_levels"
	}
	rawAdd, hasAdd := req.CreationContent["additional_creators"].([]any)
	if !hasAdd {
		return ""
	}
	for _, ac := range rawAdd {
		if acStr, isStr := ac.(string); isStr {
			if _, bad := req.PowerLevelOverride.Users[id.UserID(acStr)]; bad {
				return "v12 additional creator forbidden in power_levels"
			}
		}
	}
	return ""
}

func (m *mockTuwunel) handleMediaUpload(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := m.authUser(w, r); !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, err.Error())
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	mxc := fmt.Sprintf("mxc://%s/up%d", m.serverName, m.seq)
	m.media[mxc] = mockUploadedMedia{
		ContentType: r.Header.Get("Content-Type"),
		FileName:    r.URL.Query().Get("filename"),
		Data:        body,
	}
	writeJSON(w, http.StatusOK, map[string]string{"content_uri": mxc})
}

func (m *mockTuwunel) handleSendToDevice(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := m.authUser(w, r); !ok {
		return
	}
	m.mu.Lock()
	m.sendToDevCount++
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (m *mockTuwunel) handleUserRoutes(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/user/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "bad user route")
		return
	}
	switch {
	case parts[1] == "account_data" && len(parts) >= 3 && r.Method == http.MethodPut:
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, readErr.Error())
			return
		}
		evtType := strings.Join(parts[2:], "/")
		m.mu.Lock()
		u.AccountData[evtType] = raw
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	case len(parts) == 5 && parts[1] == "rooms" && parts[3] == "tags" && r.Method == http.MethodPut:
		var meta event.TagMetadata
		if !decodeBody(w, r, &meta) {
			return
		}
		rid := id.RoomID(parts[2])
		m.mu.Lock()
		if u.RoomTags[rid] == nil {
			u.RoomTags[rid] = make(map[string]event.TagMetadata)
		}
		u.RoomTags[rid][parts[4]] = meta
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	default:
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unhandled user route")
	}
}

func (m *mockTuwunel) handleProfileRoutes(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/displayname") && r.Method == http.MethodPut:
		var body struct {
			DisplayName string `json:"displayname"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		m.mu.Lock()
		u.DisplayName = body.DisplayName
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	case strings.HasSuffix(r.URL.Path, "/avatar_url") && r.Method == http.MethodPut:
		var body struct {
			AvatarURL string `json:"avatar_url"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		m.mu.Lock()
		u.AvatarURL = body.AvatarURL
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	default:
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unhandled profile route")
	}
}

func (m *mockTuwunel) handleRoomRoutes(w http.ResponseWriter, r *http.Request) {
	u, _, _, ok := m.authUser(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/rooms/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "bad room path")
		return
	}
	roomID := id.RoomID(parts[0])
	m.mu.Lock()
	room, exists := m.rooms[roomID]
	m.mu.Unlock()
	if !exists {
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unknown room")
		return
	}

	switch {
	case parts[1] == "join" && r.Method == http.MethodPost:
		m.mu.Lock()
		room.Members[id.UserID(u.UserID)] = true
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"room_id": roomID.String()})
	case parts[1] == "state" && len(parts) >= 4 && r.Method == http.MethodPut && parts[2] == event.StateSpaceChild.Type:
		var sc event.SpaceChildEventContent
		if !decodeBody(w, r, &sc) {
			return
		}
		m.mu.Lock()
		m.seq++
		room.SpaceChildren[parts[3]] = sc
		evID := "$st" + strconv.Itoa(m.seq)
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"event_id": evID})
	case parts[1] == "send" && len(parts) >= 4 && r.Method == http.MethodPut:
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, readErr.Error())
			return
		}
		m.mu.Lock()
		m.seq++
		evID := id.EventID("$ev" + strconv.Itoa(m.seq))
		room.Timeline = append(room.Timeline, mockRecordedEvent{
			EventID:   evID,
			Sender:    id.UserID(u.UserID),
			EventType: parts[2],
			Content:   raw,
		})
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"event_id": evID.String()})
	default:
		writeMatrixErr(w, http.StatusNotFound, mautrix.MNotFound.ErrCode, "unhandled room route")
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeMatrixErr(w, http.StatusBadRequest, mautrix.MBadJSON.ErrCode, err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		panic(err)
	}
}

func writeMatrixErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{
		"errcode": errCode,
		"error":   msg,
	})
}

type seedCryptoMaterial struct {
	ssssKey      *ssss.Key
	masterPK     olm.PKSigning
	selfPK       olm.PKSigning
	userPK       olm.PKSigning
	backupKey    *backup.MegolmBackupKey
	identityData *dump.IdentityData
	roomKeys     *dump.RoomKeysData
}

func generateTestSeedMaterial(t *testing.T, userID string, withBackup bool, encryptedRoomID string) *seedCryptoMaterial {
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

	rawSSSS := map[string]json.RawMessage{
		event.AccountDataSecretStorageDefaultKey.Type:        mustMarshalRaw(t, &ssss.DefaultSecretStorageKeyContent{KeyID: sk.ID}),
		event.AccountDataSecretStorageKey.Type + "." + sk.ID: mustMarshalRaw(t, sk.Metadata),
		event.AccountDataCrossSigningMaster.Type:             mustMarshalRaw(t, &ssss.EncryptedAccountDataEventContent{Encrypted: map[string]ssss.EncryptedKeyData{sk.ID: sk.Encrypt(event.AccountDataCrossSigningMaster.Type, masterPK.Seed())}}),
		event.AccountDataCrossSigningSelf.Type:               mustMarshalRaw(t, &ssss.EncryptedAccountDataEventContent{Encrypted: map[string]ssss.EncryptedKeyData{sk.ID: sk.Encrypt(event.AccountDataCrossSigningSelf.Type, selfPK.Seed())}}),
		event.AccountDataCrossSigningUser.Type:               mustMarshalRaw(t, &ssss.EncryptedAccountDataEventContent{Encrypted: map[string]ssss.EncryptedKeyData{sk.ID: sk.Encrypt(event.AccountDataCrossSigningUser.Type, userPK.Seed())}}),
	}

	ident := &dump.IdentityData{
		UserID:               userID,
		DefaultSSSSKeyID:     sk.ID,
		MasterSeed:           masterPK.Seed(),
		SelfSigningSeed:      selfPK.Seed(),
		UserSigningSeed:      userPK.Seed(),
		MasterPublicKey:      masterPK.PublicKey().String(),
		SelfSigningPublicKey: selfPK.PublicKey().String(),
		UserSigningPublicKey: userPK.PublicKey().String(),
		RawSSSSAccountData:   rawSSSS,
	}

	rkeys := &dump.RoomKeysData{
		UserID: userID,
		Rooms:  make(map[string]dump.RoomKeyBackupRoom),
	}
	if withBackup {
		attachTestBackup(t, sk, bk, selfPK.PublicKey(), ident, rkeys, encryptedRoomID)
	}

	return &seedCryptoMaterial{
		ssssKey:      sk,
		masterPK:     masterPK,
		selfPK:       selfPK,
		userPK:       userPK,
		backupKey:    bk,
		identityData: ident,
		roomKeys:     rkeys,
	}
}

func attachTestBackup(
	t *testing.T,
	sk *ssss.Key,
	bk *backup.MegolmBackupKey,
	selfPub id.Ed25519,
	ident *dump.IdentityData,
	rkeys *dump.RoomKeysData,
	encryptedRoomID string,
) {
	t.Helper()
	ident.RawSSSSAccountData[event.AccountDataMegolmBackupKey.Type] = mustMarshalRaw(t, &ssss.EncryptedAccountDataEventContent{
		Encrypted: map[string]ssss.EncryptedKeyData{sk.ID: sk.Encrypt(event.AccountDataMegolmBackupKey.Type, bk.Bytes())},
	})
	ident.MegolmBackupKey = bk.Bytes()
	ident.MegolmBackupPublicKey = base64.RawStdEncoding.EncodeToString(bk.PublicKey().Bytes())
	ident.KeyBackupVersion = "1"
	if encryptedRoomID == "" {
		return
	}

	ogs, err := olm.NewOutboundGroupSession()
	if err != nil {
		t.Fatalf("NewOutboundGroupSession: %v", err)
	}
	igs, err := olm.NewInboundGroupSession([]byte(ogs.Key()))
	if err != nil {
		t.Fatalf("NewInboundGroupSession: %v", err)
	}
	exp, err := igs.Export(0)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	randCurve := make([]byte, 32)
	if _, randErr := io.ReadFull(rand.Reader, randCurve); randErr != nil {
		t.Fatalf("ReadFull: %v", randErr)
	}
	encSess, err := backup.EncryptSessionData(bk, backup.MegolmSessionData{
		Algorithm:  id.AlgorithmMegolmV1,
		SenderKey:  id.Curve25519(base64.RawStdEncoding.EncodeToString(randCurve)),
		SessionKey: string(exp),
		SenderClaimedKeys: backup.SenderClaimedKeys{
			Ed25519: selfPub,
		},
	})
	if err != nil {
		t.Fatalf("EncryptSessionData: %v", err)
	}
	rkeys.Rooms[encryptedRoomID] = dump.RoomKeyBackupRoom{
		Sessions: map[string]dump.RoomKeySession{
			ogs.ID().String(): {
				SessionData:       mustMarshalRaw(t, encSess),
				FirstMessageIndex: 0,
				ForwardedCount:    0,
				IsVerified:        true,
			},
		},
	}
}

func mustMarshalRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

type importFixture struct {
	store        *dump.Store
	tuwunel      *mockTuwunel
	cfg          *config.Config
	aliceCrypto  *seedCryptoMaterial
	bobCrypto    *seedCryptoMaterial
	carolCrypto  *seedCryptoMaterial
	serverName   string
	aliceID      string
	bobID        string
	carolID      string
	dmID         string
	spaceID      string
	fedRoomID    string
	notesEncID   string
	notesPlainID string
	notesCarolID string
	noteEditBody string
	firstNoteID  string
	noteOrder    string
}

func setupImportFixture(t *testing.T, serverName string) *importFixture {
	t.Helper()
	tmpDir := filepath.Join(t.TempDir(), "dump")
	store, err := dump.Open(tmpDir)
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}

	regKey := "tuw-reg-" + serverName
	tuw := newMockTuwunel(t, serverName, regKey)

	aliceID := "@alice:" + serverName
	bobID := "@bob:" + serverName
	carolID := "@carol:" + serverName
	fedRoomID := "!fedchat:" + serverName
	dmID := "!dm:" + serverName
	spaceID := "!space-top:" + serverName
	notesEncID := "!notes-enc:" + serverName
	notesPlainID := "!notes-plain:" + serverName
	notesCarolID := "!notes-carol:" + serverName
	firstNoteID := "$oldnote1"
	noteEditBody := "Updated **first** note"
	noteOrder := "01"

	aliceMat := generateTestSeedMaterial(t, aliceID, true, fedRoomID)
	bobMat := generateTestSeedMaterial(t, bobID, true, fedRoomID)
	carolMat := generateTestSeedMaterial(t, carolID, false, "")

	tuw.addExistingUser(carolID, "pw3", false)

	avatarRef, err := store.SaveMedia("mxc://"+serverName+"/aliceav", "image/png", "alice.png", []byte("alice-png-bytes"))
	if err != nil {
		t.Fatalf("SaveMedia alice avatar: %v", err)
	}
	roomAvRef, err := store.SaveMedia("mxc://"+serverName+"/roomav", "", "room.bin", []byte("room-avatar-bytes"))
	if err != nil {
		t.Fatalf("SaveMedia room avatar: %v", err)
	}
	noteMediaRef, err := store.SaveMedia("mxc://"+serverName+"/notepic", "image/jpeg", "note.jpg", []byte("secret-note-image-payload"))
	if err != nil {
		t.Fatalf("SaveMedia note image: %v", err)
	}

	writeSeedAccountDump(t, store, aliceMat, &dump.ProfileData{
		UserID:       aliceID,
		DisplayName:  "Alice Display",
		Avatar:       avatarRef,
		IgnoredUsers: json.RawMessage(`{"ignored_users":{"@spam:example.net":{}}}`),
		Direct:       map[string][]string{bobID: {dmID}},
		RoomTags: map[string]map[string]dump.RoomTagEntry{
			dmID:      {"m.favourite": {Order: new(0.5)}},
			fedRoomID: {"m.lowpriority": {}},
		},
	}, []dump.TrustedContact{
		{UserID: bobID, MasterKey: bobMat.masterPK.PublicKey().String(), Local: true},
		{UserID: "@remote:example.org", MasterKey: "EXTKEY", Local: false},
	})

	writeSeedAccountDump(t, store, bobMat, &dump.ProfileData{
		UserID:      bobID,
		DisplayName: "Bob Display",
		Direct:      map[string][]string{aliceID: {dmID}},
	}, []dump.TrustedContact{
		{UserID: aliceID, MasterKey: aliceMat.masterPK.PublicKey().String(), Local: true},
	})

	writeSeedAccountDump(t, store, carolMat, &dump.ProfileData{UserID: carolID}, nil)

	maxLife := int64(86400000)
	minLife := int64(3600000)
	localRooms := &dump.LocalRoomsData{
		Rooms: []dump.LocalRoom{
			{
				OldRoomID:         spaceID,
				Category:          dump.RoomCategoryLocal,
				RoomType:          "m.space",
				OriginalCreator:   aliceID,
				ChosenCreator:     aliceID,
				Name:              "Family Space",
				HistoryVisibility: "invited",
				JoinRule:          "invite",
				GuestAccess:       "forbidden",
				JoinedMembers:     []string{aliceID, bobID},
				SpaceChildren: []dump.SpaceChildEntry{
					{ChildRoomID: dmID, Order: noteOrder, Suggested: true},
					{ChildRoomID: fedRoomID, Via: []string{"example.org"}},
				},
			},
			{
				OldRoomID:          dmID,
				Category:           dump.RoomCategoryLocal,
				OriginalCreator:    aliceID,
				ChosenCreator:      aliceID,
				AdditionalCreators: []string{bobID},
				Name:               "Alice & Bob DM",
				Topic:              "Private chat",
				Avatar:             roomAvRef,
				IsDirect:           true,
				Encryption:         &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1), RotationPeriodMillis: 604800000, RotationPeriodMsgs: 100},
				Retention:          &dump.RetentionConfig{MaxLifetime: &maxLife, MinLifetime: &minLife},
				HistoryVisibility:  "shared",
				JoinRule:           "invite",
				GuestAccess:        "forbidden",
				PowerLevels: &dump.PowerLevelsConfig{
					Users:         map[string]int{carolID: 50},
					Events:        map[string]int{"m.room.name": 50},
					Notifications: map[string]int{"room": 50},
					StateDefault:  50,
					Ban:           50,
					Kick:          50,
					Redact:        50,
					Invite:        25,
				},
				JoinedMembers: []string{aliceID, bobID, carolID},
			},
			{
				OldRoomID:         notesEncID,
				Category:          dump.RoomCategoryNotes,
				OriginalCreator:   aliceID,
				ChosenCreator:     aliceID,
				Name:              "Saved Messages",
				Encryption:        &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1), RotationPeriodMillis: 604800000, RotationPeriodMsgs: 100},
				HistoryVisibility: "joined",
				JoinedMembers:     []string{aliceID},
				Notes: []dump.NoteEntry{
					{
						EventID:       firstNoteID,
						MsgType:       "m.text",
						Body:          noteEditBody,
						Format:        "org.matrix.custom.html",
						FormattedBody: "<p>Updated <b>first</b> note</p>",
						Reactions:     []string{"👍"},
						Timestamp:     1700000001000,
					},
					{
						EventID:        "$oldnote2",
						MsgType:        "m.image",
						Body:           "note.jpg",
						ReplyToEventID: firstNoteID,
						Media:          noteMediaRef,
						Info:           json.RawMessage(`{"mimetype":"image/jpeg","size":25}`),
						Timestamp:      1700000002000,
					},
				},
			},
			{
				OldRoomID:       notesPlainID,
				Category:        dump.RoomCategoryNotes,
				OriginalCreator: bobID,
				ChosenCreator:   bobID,
				Name:            "Bob Plain Notes",
				JoinedMembers:   []string{bobID},
				Notes: []dump.NoteEntry{
					{
						EventID:   "$bob1",
						Body:      "Plaintext reminder",
						Reactions: []string{"✅", ""},
						Media: &dump.MediaRef{
							SHA256:   noteMediaRef.SHA256,
							FileName: "plain.dat",
						},
					},
				},
			},
			{
				OldRoomID:       notesCarolID,
				Category:        dump.RoomCategoryNotes,
				OriginalCreator: carolID,
				ChosenCreator:   carolID,
				Name:            "Carol Enc No Backup",
				Encryption:      &dump.EncryptionConfig{Algorithm: string(id.AlgorithmMegolmV1)},
				JoinedMembers:   []string{carolID},
				Notes: []dump.NoteEntry{
					{EventID: "$carol1", Body: "should skip with warn"},
				},
			},
		},
	}

	if err := store.WriteSigningKeyTOML([]byte("[global.admin]\n")); err != nil {
		t.Fatalf("WriteSigningKeyTOML: %v", err)
	}
	if err := store.WriteLocalRooms(localRooms); err != nil {
		t.Fatalf("WriteLocalRooms: %v", err)
	}
	if err := store.WriteManifest(&dump.ManifestState{
		LocalRoomMap:           make(map[string]string),
		ProvisionedUsers:       make(map[string]bool),
		ServerName:             serverName,
		LocalRoomVersion:       "12",
		ExportedAt:             "2026-11-09T20:00:00Z",
		Phase:                  dump.PhaseExported,
		ServerSigningKeyID:     tuw.serverKeyID,
		ServerSigningPublicKey: tuw.serverPubB64,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	cfg := &config.Config{
		ServerName:            serverName,
		SynapseURL:            "https://syn." + serverName,
		TuwunelURL:            tuw.srv.URL,
		TuwunelSharedSecret:   regKey,
		DataDir:               tmpDir,
		LocalRoomVersion:      "12",
		ReplaySingleUserNotes: true,
		Accounts: []config.AccountConfig{
			{
				UserID:             aliceID,
				SynapseAccessToken: "s1",
				TuwunelPassword:    "pw1",
				RecoveryKey:        aliceMat.ssssKey.RecoveryKey(),
				Admin:              true,
			},
			{
				UserID:             bobID,
				SynapseAccessToken: "s2",
				TuwunelPassword:    "pw2",
				RecoveryKey:        bobMat.ssssKey.RecoveryKey(),
				Admin:              false,
			},
			{
				UserID:             carolID,
				SynapseAccessToken: "s3",
				TuwunelPassword:    "pw3",
				RecoveryKey:        carolMat.ssssKey.RecoveryKey(),
				ExistsOnTuwunel:    true,
			},
		},
	}

	return &importFixture{
		store:        store,
		tuwunel:      tuw,
		cfg:          cfg,
		aliceCrypto:  aliceMat,
		bobCrypto:    bobMat,
		carolCrypto:  carolMat,
		serverName:   serverName,
		aliceID:      aliceID,
		bobID:        bobID,
		carolID:      carolID,
		dmID:         dmID,
		spaceID:      spaceID,
		fedRoomID:    fedRoomID,
		notesEncID:   notesEncID,
		notesPlainID: notesPlainID,
		notesCarolID: notesCarolID,
		noteEditBody: noteEditBody,
		firstNoteID:  firstNoteID,
		noteOrder:    noteOrder,
	}
}

func writeSeedAccountDump(
	t *testing.T,
	store *dump.Store,
	mat *seedCryptoMaterial,
	prof *dump.ProfileData,
	contacts []dump.TrustedContact,
) {
	t.Helper()
	if err := store.WriteIdentity(mat.identityData.UserID, mat.identityData); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := store.WriteRoomKeys(mat.identityData.UserID, mat.roomKeys); err != nil {
		t.Fatalf("WriteRoomKeys: %v", err)
	}
	if err := store.WriteProfile(mat.identityData.UserID, prof); err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}
	if err := store.WriteTrustGraph(mat.identityData.UserID, &dump.TrustGraphData{
		UserID:   mat.identityData.UserID,
		Contacts: contacts,
	}); err != nil {
		t.Fatalf("WriteTrustGraph: %v", err)
	}
}

func decryptReplayedNotes(
	t *testing.T,
	mat *seedCryptoMaterial,
	tuw *mockTuwunel,
	roomID id.RoomID,
) ([]event.MessageEventContent, []event.ReactionEventContent) {
	t.Helper()
	return decryptReplayedNotesWithKey(t, mat.identityData.UserID, mat.backupKey, tuw, roomID)
}

func decryptReplayedNotesWithKey(
	t *testing.T,
	userID string,
	backupKey *backup.MegolmBackupKey,
	tuw *mockTuwunel,
	roomID id.RoomID,
) ([]event.MessageEventContent, []event.ReactionEventContent) {
	t.Helper()
	tuw.mu.Lock()
	user := tuw.users[userID]
	room := tuw.rooms[roomID]
	sessMap := user.BackupSessions[roomID]
	timeline := append([]mockRecordedEvent(nil), room.Timeline...)
	tuw.mu.Unlock()

	if len(sessMap) == 0 {
		t.Fatalf("expected backed-up megolm sessions for replayed encrypted notes room %s", roomID)
	}

	igsBySess := importVerifiedBackupSessions(t, backupKey, roomID, sessMap)

	var msgs []event.MessageEventContent
	var reacts []event.ReactionEventContent
	for _, rec := range timeline {
		switch rec.EventType {
		case event.EventEncrypted.Type:
			var encContent event.EncryptedEventContent
			if err := json.Unmarshal(rec.Content, &encContent); err != nil {
				t.Fatalf("unmarshal encrypted note: %v", err)
			}
			igs := igsBySess[encContent.SessionID]
			if igs == nil {
				t.Fatalf("missing session %s in backup for event %s", encContent.SessionID, rec.EventID)
			}
			plainBytes, _, err := igs.Internal.Decrypt(encContent.MegolmCiphertext)
			if err != nil {
				t.Fatalf("megolm decrypt note %s: %v", rec.EventID, err)
			}
			var rawEvt struct {
				Content event.MessageEventContent `json:"content"`
			}
			if unmErr := json.Unmarshal(plainBytes, &rawEvt); unmErr != nil {
				t.Fatalf("unmarshal decrypted megolm payload: %v", unmErr)
			}
			msgs = append(msgs, rawEvt.Content)
		case event.EventReaction.Type:
			var rContent event.ReactionEventContent
			if err := json.Unmarshal(rec.Content, &rContent); err != nil {
				t.Fatalf("unmarshal reaction: %v", err)
			}
			reacts = append(reacts, rContent)
		}
	}
	return msgs, reacts
}

func importVerifiedBackupSessions(
	t *testing.T,
	backupKey *backup.MegolmBackupKey,
	roomID id.RoomID,
	sessMap map[id.SessionID]mautrix.ReqKeyBackupData,
) map[id.SessionID]*crypto.InboundGroupSession {
	t.Helper()
	igsBySess := make(map[id.SessionID]*crypto.InboundGroupSession, len(sessMap))
	for sessID, reqData := range sessMap {
		var encData backup.EncryptedSessionData[json.RawMessage]
		if err := json.Unmarshal(reqData.SessionData, &encData); err != nil {
			t.Fatalf("unmarshal backed-up session: %v", err)
		}
		decRaw, decErr := encData.Decrypt(backupKey)
		if decErr != nil {
			t.Fatalf("decrypt backed-up session: %v", decErr)
		}
		var rawFields map[string]json.RawMessage
		if err := json.Unmarshal(*decRaw, &rawFields); err != nil {
			t.Fatalf("unmarshal decrypted backup JSON object: %v", err)
		}
		if chainRaw := string(bytes.TrimSpace(rawFields["forwarding_curve25519_key_chain"])); chainRaw != "[]" {
			t.Fatalf("expected non-null empty array forwarding_curve25519_key_chain, got %q", chainRaw)
		}
		var decSess backup.MegolmSessionData
		if err := json.Unmarshal(*decRaw, &decSess); err != nil {
			t.Fatalf("unmarshal decrypted MegolmSessionData: %v", err)
		}
		if decSess.ForwardingKeyChain == nil {
			t.Fatalf("expected non-nil ForwardingKeyChain slice")
		}
		if decSess.SharedHistory == nil {
			t.Fatalf("expected SharedHistory populated in backed-up session")
		}
		igs, impErr := olm.InboundGroupSessionImport([]byte(decSess.SessionKey))
		if impErr != nil {
			t.Fatalf("InboundGroupSessionImport: %v", impErr)
		}
		igsBySess[sessID] = &crypto.InboundGroupSession{
			Internal: igs,
			RoomID:   roomID,
		}
	}
	return igsBySess
}

func verifyAttachmentContent(t *testing.T, tuw *mockTuwunel, fileInfo *event.EncryptedFileInfo, wantPlain []byte) {
	t.Helper()
	tuw.mu.Lock()
	media, ok := tuw.media[string(fileInfo.URL)]
	tuw.mu.Unlock()
	if !ok {
		t.Fatalf("uploaded encrypted media %s missing from mock Tuwunel", fileInfo.URL)
	}
	buf := append([]byte(nil), media.Data...)
	if err := fileInfo.DecryptInPlace(buf); err != nil {
		t.Fatalf("DecryptInPlace attachment: %v", err)
	}
	if !bytes.Equal(buf, wantPlain) {
		t.Fatalf("decrypted attachment mismatch: got %q want %q", string(buf), string(wantPlain))
	}
}
