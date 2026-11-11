package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	_ "maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
)

type fedMockUser struct {
	joinedRooms map[id.RoomID]bool
	roomTags    map[id.RoomID]map[string]json.RawMessage
	password    string
	deviceID    string
	masterPub   id.Ed25519
	userSignPub id.Ed25519
	selfSignPub id.Ed25519
}

type fedMockServer struct {
	server              *httptest.Server
	users               map[string]*fedMockUser
	tokens              map[string]string
	masterKeys          map[string]mautrix.CrossSigningKeys
	keyFailures         map[string]any
	joinErrors          map[string]int
	forceStatus         map[string]int
	joinViaCalls        map[string][]string
	joinCount           map[string]int
	serverName          string
	serverKeyID         string
	serverPubB64        string
	serverPriv          ed25519.PrivateKey
	sigUploadCount      int
	tagPutCount         int
	mu                  sync.Mutex
	returnedNullJoin    bool
	federationDisabled  bool
	invalidServerKeySig bool
}

func newFedMockServer(t *testing.T, serverName string) *fedMockServer {
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
	m := &fedMockServer{
		users:        make(map[string]*fedMockUser),
		tokens:       make(map[string]string),
		masterKeys:   make(map[string]mautrix.CrossSigningKeys),
		keyFailures:  make(map[string]any),
		joinErrors:   make(map[string]int),
		forceStatus:  make(map[string]int),
		joinViaCalls: make(map[string][]string),
		joinCount:    make(map[string]int),
		serverPriv:   priv,
		serverName:   serverName,
		serverKeyID:  "ed25519:a_FEDMOCK1",
		serverPubB64: base64.RawStdEncoding.EncodeToString(pub),
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handleHTTP))
	t.Cleanup(m.server.Close)
	return m
}

func (m *fedMockServer) url() string {
	return m.server.URL
}

func (m *fedMockServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if status := m.checkForcedStatus(r.Method + " " + path); status != 0 {
		writeMatrixError(w, status, "M_UNKNOWN", "forced error")
		return
	}

	routeKey := r.Method + " " + path
	switch routeKey {
	case "GET /_matrix/key/v2/server":
		m.handleServerKeys(w, r)
	case "POST /_matrix/client/v3/login":
		m.handleLogin(w, r)
	case "GET /_matrix/client/v3/account/whoami":
		m.handleWhoami(w, r)
	case "GET /_matrix/client/v3/joined_rooms":
		m.handleJoinedRooms(w, r)
	case "POST /_matrix/client/v3/keys/query":
		m.handleKeysQuery(w, r)
	case "POST /_matrix/client/v3/keys/signatures/upload":
		m.handleSignaturesUpload(w, r)
	default:
		m.handlePrefixRoute(w, r, path)
	}
}

func (m *fedMockServer) handlePrefixRoute(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case strings.HasPrefix(path, "/_matrix/client/v3/join/") && r.Method == http.MethodPost:
		m.handleJoin(w, r)
	case strings.HasPrefix(path, "/_matrix/client/v3/user/"):
		m.handleUserRoutes(w, r)
	default:
		writeMatrixError(w, http.StatusNotFound, "M_UNRECOGNIZED", "unhandled route: "+r.Method+" "+path)
	}
}

func (m *fedMockServer) checkForcedStatus(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if code, ok := m.forceStatus[key]; ok {
		return code
	}
	return 0
}

func (m *fedMockServer) handleServerKeys(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	disabled := m.federationDisabled
	badSig := m.invalidServerKeySig
	serverName := m.serverName
	keyID := m.serverKeyID
	pubB64 := m.serverPubB64
	priv := m.serverPriv
	m.mu.Unlock()

	if disabled {
		writeMatrixError(w, http.StatusForbidden, mautrix.MForbidden.ErrCode, "Federation is disabled")
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
	sigBytes := ed25519.Sign(priv, canon)
	if badSig {
		sigBytes[0] ^= 0xff
	}
	payload["signatures"] = map[string]any{
		serverName: map[string]string{
			keyID: base64.RawStdEncoding.EncodeToString(sigBytes),
		},
	}
	writeJSONResponse(w, http.StatusOK, payload)
}

func (m *fedMockServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqLogin
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMatrixError(w, http.StatusBadRequest, "M_BAD_JSON", err.Error())
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[req.Identifier.User]
	if !ok || user.password != req.Password {
		writeMatrixError(w, http.StatusForbidden, "M_FORBIDDEN", "bad credentials")
		return
	}
	token := fmt.Sprintf("tok-%s-%d", user.deviceID, len(m.tokens)+1)
	m.tokens[token] = req.Identifier.User
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"user_id":      req.Identifier.User,
		"access_token": token,
		"device_id":    user.deviceID,
	})
}

func (m *fedMockServer) handleWhoami(w http.ResponseWriter, r *http.Request) {
	userID, u, ok := m.authUser(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	m.mu.Lock()
	devID := u.deviceID
	m.mu.Unlock()
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"user_id":   userID,
		"device_id": devID,
	})
}

func (m *fedMockServer) handleJoinedRooms(w http.ResponseWriter, r *http.Request) {
	_, u, ok := m.authUser(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnedNullJoin {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("null")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	rooms := make([]id.RoomID, 0, len(u.joinedRooms))
	for rid, joined := range u.joinedRooms {
		if joined {
			rooms = append(rooms, rid)
		}
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"joined_rooms": rooms})
}

func (m *fedMockServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	userID, u, ok := m.authUser(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	rawRoom := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/join/")
	roomIDStr, err := url.PathUnescape(rawRoom)
	if err != nil {
		roomIDStr = rawRoom
	}
	key := userID + "|" + roomIDStr

	m.mu.Lock()
	defer m.mu.Unlock()
	if code, fail := m.joinErrors[key]; fail {
		writeMatrixError(w, code, "M_UNKNOWN", "remote join failed")
		return
	}
	if code, fail := m.joinErrors[roomIDStr]; fail {
		writeMatrixError(w, code, "M_UNKNOWN", "remote join failed")
		return
	}
	via := r.URL.Query()["via"]
	m.joinViaCalls[key] = slices.Clone(via)
	m.joinCount[key]++
	u.joinedRooms[id.RoomID(roomIDStr)] = true
	writeJSONResponse(w, http.StatusOK, map[string]any{"room_id": roomIDStr})
}

func (m *fedMockServer) handleUserRoutes(w http.ResponseWriter, r *http.Request) {
	_, u, ok := m.authUser(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_matrix/client/v3/user/")
	parts := strings.Split(rest, "/")
	if len(parts) < 4 || parts[1] != "rooms" || parts[3] != "tags" {
		writeMatrixError(w, http.StatusNotFound, "M_NOT_FOUND", "unknown user route")
		return
	}
	roomID := id.RoomID(parts[2])
	tagName := strings.Join(parts[4:], "/")

	switch r.Method {
	case http.MethodGet:
		if len(parts) != 4 {
			writeMatrixError(w, http.StatusNotFound, "M_NOT_FOUND", "unexpected tag path")
			return
		}
		m.mu.Lock()
		tags := u.roomTags[roomID]
		if len(tags) == 0 {
			m.mu.Unlock()
			writeMatrixError(w, http.StatusNotFound, "M_NOT_FOUND", "no tags")
			return
		}
		out := make(map[string]json.RawMessage, len(tags))
		for k, v := range tags {
			out[k] = slices.Clone(v)
		}
		m.mu.Unlock()
		writeJSONResponse(w, http.StatusOK, map[string]any{"tags": out})
	case http.MethodPut:
		if len(parts) < 5 || tagName == "" {
			writeMatrixError(w, http.StatusBadRequest, "M_INVALID_PARAM", "missing tag name")
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			writeMatrixError(w, http.StatusBadRequest, "M_BAD_JSON", readErr.Error())
			return
		}
		m.mu.Lock()
		if u.roomTags[roomID] == nil {
			u.roomTags[roomID] = make(map[string]json.RawMessage)
		}
		u.roomTags[roomID][tagName] = body
		m.tagPutCount++
		m.mu.Unlock()
		writeJSONResponse(w, http.StatusOK, map[string]any{})
	default:
		writeMatrixError(w, http.StatusMethodNotAllowed, "M_UNRECOGNIZED", "bad tag method")
	}
}

func (m *fedMockServer) handleKeysQuery(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := m.authUser(r); !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	var req mautrix.ReqQueryKeys
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMatrixError(w, http.StatusBadRequest, "M_BAD_JSON", err.Error())
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	masterOut := make(map[id.UserID]mautrix.CrossSigningKeys)
	for uid := range req.DeviceKeys {
		if mk, ok := m.masterKeys[uid.String()]; ok {
			masterOut[uid] = mk
		}
	}
	failuresOut := make(map[string]any, len(m.keyFailures))
	maps.Copy(failuresOut, m.keyFailures)
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"master_keys": masterOut,
		"failures":    failuresOut,
	})
}

func (m *fedMockServer) handleSignaturesUpload(w http.ResponseWriter, r *http.Request) {
	signerID, _, ok := m.authUser(r)
	if !ok {
		writeMatrixError(w, http.StatusUnauthorized, "M_UNKNOWN_TOKEN", "invalid token")
		return
	}
	var payload map[string]map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeMatrixError(w, http.StatusBadRequest, "M_BAD_JSON", err.Error())
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sigUploadCount++
	for targetUID, byKey := range payload {
		for _, rawObj := range byKey {
			var parsed mautrix.CrossSigningKeys
			if err := json.Unmarshal(rawObj, &parsed); err != nil {
				continue
			}
			existing, exists := m.masterKeys[targetUID]
			if !exists {
				continue
			}
			if existing.Signatures == nil {
				existing.Signatures = make(signatures.Signatures)
			}
			signerUID := id.UserID(signerID)
			if existing.Signatures[signerUID] == nil {
				existing.Signatures[signerUID] = make(map[id.KeyID]string)
			}
			maps.Copy(existing.Signatures[signerUID], parsed.Signatures[signerUID])
			m.masterKeys[targetUID] = existing
		}
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"failures": map[string]any{}})
}

func (m *fedMockServer) authUser(r *http.Request) (string, *fedMockUser, bool) {
	auth := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(auth, "Bearer ")
	if !found || token == "" {
		return "", nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	userID, ok := m.tokens[token]
	if !ok {
		return "", nil, false
	}
	u, exists := m.users[userID]
	return userID, u, exists
}

func writeJSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeMatrixError(w http.ResponseWriter, status int, code, msg string) {
	writeJSONResponse(w, status, map[string]any{
		"errcode": code,
		"error":   msg,
	})
}

type fedFixture struct {
	srv           *fedMockServer
	store         *dump.Store
	cfg           *config.Config
	aliceUserKP   olm.PKSigning
	aliceID       string
	bobID         string
	carolID       string
	daveID        string
	fedRoomOne    string
	fedRoomTwo    string
	carolMaster   id.Ed25519
	daveMaster    id.Ed25519
	fedRoomOneVia []string
}

func setupFedFixture(t *testing.T, serverName string) *fedFixture {
	t.Helper()
	srv := newFedMockServer(t, serverName)
	store, err := dump.Open(filepath.Join(t.TempDir(), "dump"))
	if err != nil {
		t.Fatalf("dump.Open: %v", err)
	}

	aliceID := "@alice:" + serverName
	bobID := "@bob:" + serverName
	carolID := "@carol:partner.example.org"
	daveID := "@dave:remote.example.net"
	fedRoomOne := "!fed1:partner.example.org"
	fedRoomTwo := "!fed2:remote.example.net"
	fedRoomOneVia := []string{"partner.example.org", "backup.example.net"}

	aliceMaster, aliceMasterSeed := generateSigningPair(t)
	aliceSelf, aliceSelfSeed := generateSigningPair(t)
	aliceUser, aliceUserSeed := generateSigningPair(t)
	bobMaster, bobMasterSeed := generateSigningPair(t)
	bobSelf, bobSelfSeed := generateSigningPair(t)
	bobUser, bobUserSeed := generateSigningPair(t)
	carolMaster, _ := generateSigningPair(t)
	daveMaster, _ := generateSigningPair(t)

	srv.mu.Lock()
	srv.users[aliceID] = &fedMockUser{
		password:    "alice-pw",
		deviceID:    "ALICEDEV",
		joinedRooms: map[id.RoomID]bool{id.RoomID(fedRoomTwo): true},
		roomTags:    make(map[id.RoomID]map[string]json.RawMessage),
		masterPub:   aliceMaster.PublicKey(),
		selfSignPub: aliceSelf.PublicKey(),
		userSignPub: aliceUser.PublicKey(),
	}
	srv.tokens["alice-valid-token"] = aliceID

	existingBobOrder := json.RawMessage(`{"order":0.5}`)
	oldBobOrder := json.RawMessage(`{"order":0.1}`)
	srv.users[bobID] = &fedMockUser{
		password:    "bob-pw",
		deviceID:    "BOBDEV",
		joinedRooms: map[id.RoomID]bool{id.RoomID(fedRoomOne): true},
		roomTags: map[id.RoomID]map[string]json.RawMessage{
			id.RoomID(fedRoomOne): {
				"m.lowpriority": existingBobOrder,
				"u.updated":     oldBobOrder,
			},
		},
		masterPub:   bobMaster.PublicKey(),
		selfSignPub: bobSelf.PublicKey(),
		userSignPub: bobUser.PublicKey(),
	}
	srv.masterKeys[carolID] = buildMasterKeyObj(carolID, carolMaster.PublicKey())
	srv.masterKeys[daveID] = buildMasterKeyObj(daveID, daveMaster.PublicKey())
	srv.mu.Unlock()

	if err := store.WriteSession(aliceID, &dump.SessionData{
		UserID:        aliceID,
		HomeserverURL: srv.url(),
		AccessToken:   "alice-valid-token",
		DeviceID:      "ALICEDEV",
	}); err != nil {
		t.Fatalf("WriteSession alice: %v", err)
	}
	if err := store.WriteSession(bobID, &dump.SessionData{
		UserID:        bobID,
		HomeserverURL: srv.url(),
		AccessToken:   "bob-expired-token",
		DeviceID:      "OLDDEV",
	}); err != nil {
		t.Fatalf("WriteSession bob: %v", err)
	}

	writeAccountFedArtifacts(t, store, aliceID, aliceMaster, aliceSelf, aliceUser, aliceMasterSeed, aliceSelfSeed, aliceUserSeed,
		map[string]map[string]dump.RoomTagEntry{
			fedRoomOne: {
				"m.favourite": {Order: new(0.25)},
				"u.notes":     {},
			},
			fedRoomTwo: {
				"u.work": {Order: new(0.8)},
			},
		},
		[]dump.TrustedContact{
			{UserID: bobID, MasterKey: bobMaster.PublicKey().String(), Local: true},
			{UserID: aliceID, MasterKey: aliceMaster.PublicKey().String(), Local: false},
			{UserID: carolID, MasterKey: carolMaster.PublicKey().String(), Local: false},
			{UserID: daveID, MasterKey: daveMaster.PublicKey().String(), Local: false},
		},
	)

	writeAccountFedArtifacts(t, store, bobID, bobMaster, bobSelf, bobUser, bobMasterSeed, bobSelfSeed, bobUserSeed,
		map[string]map[string]dump.RoomTagEntry{
			fedRoomOne: {
				"m.lowpriority": {Order: new(0.5)},
				"u.updated":     {Order: new(0.9)},
			},
		},
		nil,
	)

	if err := store.WriteFederatedRooms(&dump.FederatedRoomsData{
		Rooms: []dump.FederatedRoom{
			{
				RoomID:           fedRoomOne,
				JoinedLocalUsers: []string{aliceID, bobID},
				ViaServers:       slices.Clone(fedRoomOneVia),
			},
			{
				RoomID:           fedRoomTwo,
				JoinedLocalUsers: []string{aliceID},
				ViaServers:       []string{"remote.example.net"},
			},
		},
	}); err != nil {
		t.Fatalf("WriteFederatedRooms: %v", err)
	}

	if err := store.WriteManifest(&dump.ManifestState{
		ServerName:             serverName,
		LocalRoomVersion:       "12",
		ExportedAt:             "2026-01-01T00:00:00Z",
		Phase:                  dump.PhaseImportedLocal,
		LocalRoomMap:           map[string]string{"!old:" + serverName: "!new:" + serverName},
		ProvisionedUsers:       map[string]bool{aliceID: true, bobID: true},
		ServerSigningKeyID:     srv.serverKeyID,
		ServerSigningPublicKey: srv.serverPubB64,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	cfg := &config.Config{
		ServerName: serverName,
		SynapseURL: "https://synapse." + serverName,
		TuwunelURL: srv.url(),
		DataDir:    store.Root(),
		Accounts: []config.AccountConfig{
			{
				UserID:          aliceID,
				TuwunelPassword: "alice-pw",
				RecoveryKey:     "EsTfakeKeyOne",
			},
			{
				UserID:          bobID,
				TuwunelPassword: "bob-pw",
				RecoveryKey:     "EsTfakeKeyTwo",
			},
		},
	}

	return &fedFixture{
		srv:           srv,
		store:         store,
		cfg:           cfg,
		aliceUserKP:   aliceUser,
		aliceID:       aliceID,
		bobID:         bobID,
		carolID:       carolID,
		daveID:        daveID,
		fedRoomOne:    fedRoomOne,
		fedRoomTwo:    fedRoomTwo,
		fedRoomOneVia: fedRoomOneVia,
		carolMaster:   carolMaster.PublicKey(),
		daveMaster:    daveMaster.PublicKey(),
	}
}

func writeAccountFedArtifacts(
	t *testing.T,
	store *dump.Store,
	userID string,
	masterKP, selfKP, userKP olm.PKSigning,
	masterSeed, selfSeed, userSeed []byte,
	roomTags map[string]map[string]dump.RoomTagEntry,
	contacts []dump.TrustedContact,
) {
	t.Helper()
	if err := store.WriteIdentity(userID, &dump.IdentityData{
		UserID:               userID,
		MasterSeed:           masterSeed,
		SelfSigningSeed:      selfSeed,
		UserSigningSeed:      userSeed,
		MasterPublicKey:      masterKP.PublicKey().String(),
		SelfSigningPublicKey: selfKP.PublicKey().String(),
		UserSigningPublicKey: userKP.PublicKey().String(),
	}); err != nil {
		t.Fatalf("WriteIdentity %s: %v", userID, err)
	}
	if err := store.WriteProfile(userID, &dump.ProfileData{
		UserID:   userID,
		RoomTags: roomTags,
	}); err != nil {
		t.Fatalf("WriteProfile %s: %v", userID, err)
	}
	if err := store.WriteTrustGraph(userID, &dump.TrustGraphData{
		UserID:   userID,
		Contacts: contacts,
	}); err != nil {
		t.Fatalf("WriteTrustGraph %s: %v", userID, err)
	}
}

func generateSigningPair(t *testing.T) (kp olm.PKSigning, seed []byte) {
	t.Helper()
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	kp, err := olm.NewPKSigningFromSeed(seed)
	if err != nil {
		t.Fatalf("NewPKSigningFromSeed: %v", err)
	}
	return kp, seed
}

func buildMasterKeyObj(userID string, pub id.Ed25519) mautrix.CrossSigningKeys {
	return mautrix.CrossSigningKeys{
		UserID: id.UserID(userID),
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, pub.String()): pub,
		},
	}
}

func verifySignatureOnMock(t *testing.T, srv *fedMockServer, targetUID, signerUID string, signerPub id.Ed25519) bool {
	t.Helper()
	srv.mu.Lock()
	mk := srv.masterKeys[targetUID]
	srv.mu.Unlock()
	ok, err := signatures.VerifySignatureJSON(&mk, id.UserID(signerUID), signerPub.String(), signerPub)
	return err == nil && ok
}
