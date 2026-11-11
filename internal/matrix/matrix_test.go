package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	_ "maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/matrix/sharedsecretmac"
)

type failingReader struct {
	err error
}

func (f failingReader) Read([]byte) (int, error) {
	return 0, f.err
}

type failingCloseBody struct {
	reader   io.Reader
	closeErr error
}

func (b *failingCloseBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *failingCloseBody) Close() error {
	return b.closeErr
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingCryptoStore struct {
	*crypto.MemoryStore
	loadErr error
}

func (s *failingCryptoStore) GetAccount(ctx context.Context) (*crypto.OlmAccount, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.MemoryStore.GetAccount(ctx)
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode test JSON response: %v", err)
	}
}

func writeMatrixError(t *testing.T, w http.ResponseWriter, status int, code, msg string) {
	t.Helper()
	writeJSONResponse(t, w, status, map[string]string{
		"errcode": code,
		"error":   msg,
	})
}

func writeRawResponse(t *testing.T, w http.ResponseWriter, status int, contentType string, body []byte) {
	t.Helper()
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write raw test response: %v", err)
	}
}

func TestNewClient(t *testing.T) {
	log := zerolog.Nop()
	cli, err := NewClient(" https://alpha.example.com/// ", "@alice:alpha.example.com", "example-bearer-1", &log)
	if err != nil {
		t.Fatalf("NewClient valid err = %v", err)
	}
	if cli.HomeserverURL.String() != "https://alpha.example.com" {
		t.Errorf("HomeserverURL = %q, want trailing slash trimmed", cli.HomeserverURL.String())
	}
	if cli.UserAgent != defaultUserAgent {
		t.Errorf("UserAgent = %q, want %q", cli.UserAgent, defaultUserAgent)
	}

	nilLogCli, err := NewClient("https://beta.example.net", "@bob:beta.example.net", "example-bearer-2", nil)
	if err != nil {
		t.Fatalf("NewClient nil log err = %v", err)
	}
	if nilLogCli.Client == nil || nilLogCli.Client.Timeout != defaultHTTPTimeout {
		t.Errorf("expected initialized HTTP client with timeout %v", defaultHTTPTimeout)
	}

	if _, badErr := NewClient("://invalid-url", "@carol:gamma.example.org", "", nil); badErr == nil {
		t.Errorf("expected error for malformed homeserver URL, got nil")
	}
}

func TestLoginPassword(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		userID            string
		credential        string
		deviceDisplayName string
		wantDisplayName   string
		serverStatus      int
		wantErr           bool
	}{
		{
			name:              "success with default device display name",
			userID:            "@alice:login1.example.com",
			credential:        "val-1",
			deviceDisplayName: "   ",
			wantDisplayName:   DefaultDeviceDisplayName,
			serverStatus:      http.StatusOK,
		},
		{
			name:              "success with custom device display name",
			userID:            "@bob:login2.example.net",
			credential:        "val-2",
			deviceDisplayName: "custom-migrator",
			wantDisplayName:   "custom-migrator",
			serverStatus:      http.StatusOK,
		},
		{
			name:              "forbidden credentials fail cleanly",
			userID:            "@carol:login3.example.org",
			credential:        "val-3",
			deviceDisplayName: "test-dev",
			wantDisplayName:   "test-dev",
			serverStatus:      http.StatusForbidden,
			wantErr:           true,
		},
	}

	for _, tc := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/_matrix/client/v3/login" {
				t.Errorf("%s: unexpected path %q", tc.name, r.URL.Path)
			}
			var payload map[string]any
			if decErr := json.NewDecoder(r.Body).Decode(&payload); decErr != nil {
				t.Fatalf("decode login body: %v", decErr)
			}
			if payload["initial_device_display_name"] != tc.wantDisplayName {
				t.Errorf("%s: display name = %v, want %q", tc.name, payload["initial_device_display_name"], tc.wantDisplayName)
			}
			if tc.serverStatus != http.StatusOK {
				writeMatrixError(t, w, tc.serverStatus, "M_FORBIDDEN", "Invalid login")
				return
			}
			writeJSONResponse(t, w, http.StatusOK, mautrix.RespLogin{
				UserID:      id.UserID(tc.userID),
				AccessToken: "tok-login",
				DeviceID:    id.DeviceID("DEV1"),
			})
		}))

		cli, resp, err := LoginPassword(ctx, srv.URL, tc.userID, tc.credential, tc.deviceDisplayName, nil)
		srv.Close()
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: LoginPassword err = %v", tc.name, err)
		}
		if cli.UserID.String() != tc.userID || resp.DeviceID != "DEV1" {
			t.Errorf("%s: unexpected login result user=%q device=%q", tc.name, cli.UserID, resp.DeviceID)
		}
	}

	if _, _, badURLErr := LoginPassword(ctx, "://bad", "@dave:login4.example", "pass", "", nil); badURLErr == nil {
		t.Errorf("expected LoginPassword bad URL error, got nil")
	}
}

func TestConnectWithToken(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		wantErr        error
		name           string
		expectedUserID string
		serverUserID   string
		serverDeviceID string
		serverStatus   int
		anyErr         bool
	}{
		{
			name:           "matching token and user ID populates device ID",
			expectedUserID: "@alice:whoami1.example.com",
			serverUserID:   "@alice:whoami1.example.com",
			serverDeviceID: "DEVWHOAMI",
			serverStatus:   http.StatusOK,
		},
		{
			name:           "user ID mismatch fails with ErrWhoamiMismatch",
			expectedUserID: "@alice:whoami2.example.net",
			serverUserID:   "@bob:whoami2.example.net",
			serverDeviceID: "DEV2",
			serverStatus:   http.StatusOK,
			wantErr:        ErrWhoamiMismatch,
		},
		{
			name:           "unauthorized token fails",
			expectedUserID: "@carol:whoami3.example.org",
			serverStatus:   http.StatusUnauthorized,
			anyErr:         true,
		},
	}

	for _, tc := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/_matrix/client/v3/account/whoami" {
				t.Errorf("%s: unexpected path %q", tc.name, r.URL.Path)
			}
			if tc.serverStatus != http.StatusOK {
				writeMatrixError(t, w, tc.serverStatus, "M_UNKNOWN_TOKEN", "Unknown bearer")
				return
			}
			writeJSONResponse(t, w, http.StatusOK, mautrix.RespWhoami{
				UserID:   id.UserID(tc.serverUserID),
				DeviceID: id.DeviceID(tc.serverDeviceID),
			})
		}))

		cli, resp, err := ConnectWithToken(ctx, srv.URL, tc.expectedUserID, "bearer-test", nil)
		srv.Close()
		if tc.anyErr {
			if err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
			continue
		}
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: ConnectWithToken err = %v", tc.name, err)
		}
		if cli.DeviceID.String() != tc.serverDeviceID || resp.DeviceID.String() != tc.serverDeviceID {
			t.Errorf("%s: DeviceID = %q, want %q", tc.name, cli.DeviceID, tc.serverDeviceID)
		}
	}

	if _, _, badURLErr := ConnectWithToken(ctx, "://bad", "@dave:whoami4.example", "tok", nil); badURLErr == nil {
		t.Errorf("expected ConnectWithToken bad URL error, got nil")
	}
}

func TestNewOlmMachine(t *testing.T) {
	ctx := t.Context()
	if _, _, err := NewOlmMachine(ctx, nil, nil); !errors.Is(err, ErrNilClient) {
		t.Fatalf("NewOlmMachine(nil) err = %v, want %v", err, ErrNilClient)
	}

	cli, err := NewClient("https://olm.example.com", "@alice:olm.example.com", "tok-1", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	mach, store, err := NewOlmMachine(ctx, cli, nil)
	if err != nil {
		t.Fatalf("NewOlmMachine nil log err = %v", err)
	}
	if !mach.DisableDecryptKeyFetching || store.Members == nil {
		t.Errorf("expected DisableDecryptKeyFetching=true and initialized state store maps")
	}

	log := zerolog.Nop()
	mach2, _, err := NewOlmMachine(ctx, cli, &log)
	if err != nil || mach2 == nil {
		t.Fatalf("NewOlmMachine with logger err = %v", err)
	}

	badStore := &failingCryptoStore{
		MemoryStore: crypto.NewMemoryStore(nil),
		loadErr:     errors.New("crypto store read failed"),
	}
	badMach := crypto.NewOlmMachine(cli, &log, badStore, store)
	if loadErr := defaultMachineLoad(ctx, badMach); loadErr == nil {
		t.Fatalf("expected defaultMachineLoad error from failing crypto store")
	}

	origLoad := machineLoad
	t.Cleanup(func() {
		machineLoad = origLoad
	})
	sentinel := errors.New("injected load failure")
	machineLoad = func(context.Context, *crypto.OlmMachine) error {
		return sentinel
	}
	if _, _, loadErr := NewOlmMachine(ctx, cli, nil); !errors.Is(loadErr, sentinel) {
		t.Errorf("NewOlmMachine load error = %v, want %v", loadErr, sentinel)
	}
}

func TestPasswordUIACallback(t *testing.T) {
	cb := PasswordUIACallback(id.UserID("@alice:uia.example.com"), "uia-val")
	if got := cb(nil); got != nil {
		t.Fatalf("cb(nil) = %v, want nil", got)
	}

	tests := []struct {
		wantType any
		name     string
		stages   []mautrix.AuthType
		wantNil  bool
	}{
		{
			name:     "password stage selected when present",
			stages:   []mautrix.AuthType{mautrix.AuthTypeDummy, mautrix.AuthTypePassword},
			wantType: mautrix.AuthTypePassword,
		},
		{
			name:     "dummy stage fallback",
			stages:   []mautrix.AuthType{mautrix.AuthTypeDummy},
			wantType: mautrix.AuthTypeDummy,
		},
		{
			name:    "unsupported stages return nil",
			stages:  []mautrix.AuthType{mautrix.AuthTypeSSO},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		resp := &mautrix.RespUserInteractive{
			Session: "uia-sess-1",
			Flows: []mautrix.UIAFlow{
				{Stages: tc.stages},
			},
		}
		got := cb(resp)
		if tc.wantNil {
			if got != nil {
				t.Errorf("%s: got %v, want nil", tc.name, got)
			}
			continue
		}
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: expected map[string]any, got %T", tc.name, got)
		}
		if m[uiaFieldType] != tc.wantType || m["session"] != "uia-sess-1" {
			t.Errorf("%s: got payload %+v, want type %v", tc.name, m, tc.wantType)
		}
	}
}

func TestRegisterSharedSecretSuccess(t *testing.T) {
	ctx := t.Context()
	sharedKey := "test-shared-secret-success"

	tests := []struct {
		name     string
		username string
		domain   string
		nonce    string
		phrase   string
		deviceID string
		admin    bool
	}{
		{
			name:     "registers non-admin user with valid HMAC",
			username: "bob",
			domain:   "reg1.example.com",
			nonce:    "nonce-bob",
			phrase:   "phrase-1",
			deviceID: "DEVBOB",
			admin:    false,
		},
		{
			name:     "registers admin user cleanly",
			username: "alice",
			domain:   "reg2.example.net",
			nonce:    "nonce-alice",
			phrase:   "phrase-2",
			deviceID: "DEVALICE",
			admin:    true,
		},
	}

	for _, tc := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != adminRegisterPath {
				t.Errorf("%s: unexpected path %q", tc.name, r.URL.Path)
			}
			switch r.Method {
			case http.MethodGet:
				writeJSONResponse(t, w, http.StatusOK, map[string]string{"nonce": tc.nonce})
			case http.MethodPost:
				var reqBody struct {
					Nonce    string `json:"nonce"`
					Username string `json:"username"`
					Phrase   string `json:"password"`
					MAC      string `json:"mac"`
					Admin    bool   `json:"admin"`
				}
				if decErr := json.NewDecoder(r.Body).Decode(&reqBody); decErr != nil {
					t.Fatalf("decode submit JSON: %v", decErr)
				}
				wantMAC := sharedsecretmac.Compute(sharedKey, reqBody.Nonce, tc.username, tc.phrase, tc.admin)
				if reqBody.MAC != wantMAC || reqBody.Admin != tc.admin {
					t.Errorf("%s: invalid HMAC or admin flag", tc.name)
				}
				writeJSONResponse(t, w, http.StatusOK, RegisterResponse{
					AccessToken: "tok-" + tc.username,
					HomeServer:  tc.domain,
					UserID:      "@" + tc.username + ":" + tc.domain,
					DeviceID:    tc.deviceID,
				})
			}
		}))

		got, err := RegisterSharedSecret(ctx, srv.URL, sharedKey, tc.username, tc.phrase, tc.admin)
		srv.Close()
		if err != nil {
			t.Fatalf("%s: RegisterSharedSecret err = %v", tc.name, err)
		}
		if got.DeviceID != tc.deviceID || got.HomeServer != tc.domain {
			t.Errorf("%s: unexpected RegisterResponse: %+v", tc.name, got)
		}
	}
}

func TestRegisterSharedSecretErrors(t *testing.T) {
	ctx := t.Context()
	sharedKey := "test-shared-secret-errors"

	if _, err := RegisterSharedSecret(ctx, "https://regerr.example.com", "", "alice", "phrase", false); !errors.Is(err, ErrEmptySharedSecret) {
		t.Fatalf("empty shared secret err = %v, want %v", err, ErrEmptySharedSecret)
	}
	if _, err := RegisterSharedSecret(ctx, "http://\x7f.example.com", sharedKey, "alice", "phrase", false); err == nil {
		t.Fatalf("expected invalid control-char URL to fail nonce request build")
	}

	tests := []struct {
		wantErr      error
		name         string
		nonceBody    string
		submitBody   string
		nonceStatus  int
		submitStatus int
		anyErr       bool
	}{
		{
			name:        "nonce endpoint HTTP error",
			nonceStatus: http.StatusServiceUnavailable,
			nonceBody:   "busy",
			wantErr:     ErrAdminRegisterFailed,
		},
		{
			name:        "nonce endpoint invalid JSON",
			nonceStatus: http.StatusOK,
			nonceBody:   "{not-json",
			anyErr:      true,
		},
		{
			name:        "empty nonce rejected",
			nonceStatus: http.StatusOK,
			nonceBody:   `{"nonce":""}`,
			wantErr:     ErrEmptyNonce,
		},
		{
			name:         "submit endpoint HTTP error",
			nonceStatus:  http.StatusOK,
			nonceBody:    `{"nonce":"nonce-fail"}`,
			submitStatus: http.StatusBadRequest,
			submitBody:   "user exists",
			wantErr:      ErrAdminRegisterFailed,
		},
		{
			name:         "submit endpoint invalid JSON",
			nonceStatus:  http.StatusOK,
			nonceBody:    `{"nonce":"nonce-broken"}`,
			submitStatus: http.StatusOK,
			submitBody:   "{broken-json",
			anyErr:       true,
		},
	}

	for _, tc := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				writeRawResponse(t, w, tc.nonceStatus, "application/json", []byte(tc.nonceBody))
				return
			}
			writeRawResponse(t, w, tc.submitStatus, "application/json", []byte(tc.submitBody))
		}))

		_, err := RegisterSharedSecret(ctx, srv.URL, sharedKey, "carol", "phrase", false)
		srv.Close()
		if tc.anyErr {
			if err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
			continue
		}
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestRegisterSharedSecretTransportErrors(t *testing.T) {
	ctx := t.Context()
	sharedKey := "test-shared-secret-transport"

	if _, err := defaultJSONMarshal(make(chan int)); err == nil {
		t.Errorf("expected defaultJSONMarshal(chan) to fail")
	}

	marshalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeRawResponse(t, w, http.StatusOK, "application/json", []byte(`{"nonce":"n1"}`))
	}))
	t.Cleanup(marshalSrv.Close)

	origMarshal := jsonMarshal
	t.Cleanup(func() {
		jsonMarshal = origMarshal
	})
	marshalErr := errors.New("injected marshal error")
	jsonMarshal = func(any) ([]byte, error) {
		return nil, marshalErr
	}
	if _, err := RegisterSharedSecret(ctx, marshalSrv.URL, sharedKey, "erin", "phrase", false); !errors.Is(err, marshalErr) {
		t.Errorf("RegisterSharedSecret jsonMarshal err = %v, want %v", err, marshalErr)
	}

	jsonMarshal = origMarshal
	hijackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeRawResponse(t, w, http.StatusOK, "application/json", []byte(`{"nonce":"n2"}`))
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("ResponseWriter does not support Hijack")
		}
		conn, _, hjErr := hj.Hijack()
		if hjErr != nil {
			t.Fatalf("Hijack: %v", hjErr)
		}
		if closeErr := conn.Close(); closeErr != nil {
			t.Fatalf("close hijacked conn: %v", closeErr)
		}
	}))
	t.Cleanup(hijackSrv.Close)

	if _, err := RegisterSharedSecret(ctx, hijackSrv.URL, sharedKey, "frank", "phrase", false); err == nil {
		t.Errorf("expected POST transport error after hijacked connection close")
	}
}

func TestDownloadMediaWithFallbackSuccess(t *testing.T) {
	ctx := t.Context()
	mxc := id.ContentURI{Homeserver: "media1.example.com", FileID: "media-id-1"}

	tests := []struct {
		name         string
		v1Type       string
		v1ErrCode    string
		v3Type       string
		v1Body       []byte
		v3Body       []byte
		wantBody     []byte
		v1Status     int
		wantV3Called bool
	}{
		{
			name:     "v1 authenticated endpoint succeeds directly",
			v1Status: http.StatusOK,
			v1Type:   "image/png",
			v1Body:   []byte("png-v1-bytes"),
			wantBody: []byte("png-v1-bytes"),
		},
		{
			name:         "v1 404 falls back to v3 legacy media",
			v1Status:     http.StatusNotFound,
			v1ErrCode:    "M_NOT_FOUND",
			v3Type:       "image/jpeg",
			v3Body:       []byte("jpeg-legacy"),
			wantBody:     []byte("jpeg-legacy"),
			wantV3Called: true,
		},
		{
			name:         "v1 M_UNRECOGNIZED falls back to v3 legacy media",
			v1Status:     http.StatusBadRequest,
			v1ErrCode:    mautrix.MUnrecognized.ErrCode,
			v3Type:       "text/plain",
			v3Body:       []byte("plain-legacy"),
			wantBody:     []byte("plain-legacy"),
			wantV3Called: true,
		},
	}

	for _, tc := range tests {
		v3Called := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_matrix/client/v1/media/download/media1.example.com/media-id-1":
				if tc.v1Status == http.StatusOK {
					writeRawResponse(t, w, tc.v1Status, tc.v1Type, tc.v1Body)
					return
				}
				writeMatrixError(t, w, tc.v1Status, tc.v1ErrCode, "not available")
			case "/_matrix/media/v3/download/media1.example.com/media-id-1":
				v3Called = true
				if r.Header.Get("Authorization") != "Bearer media-bearer" {
					t.Errorf("%s: missing bearer auth header on v3 fallback", tc.name)
				}
				writeRawResponse(t, w, http.StatusOK, tc.v3Type, tc.v3Body)
			default:
				t.Errorf("%s: unexpected path %q", tc.name, r.URL.Path)
			}
		}))

		cli, err := NewClient(srv.URL, "@alice:media1.example.com", "media-bearer", nil)
		if err != nil {
			srv.Close()
			t.Fatalf("NewClient: %v", err)
		}
		gotBody, gotType, dlErr := DownloadMediaWithFallback(ctx, cli, mxc)
		srv.Close()

		if dlErr != nil {
			t.Fatalf("%s: unexpected err = %v", tc.name, dlErr)
		}
		if v3Called != tc.wantV3Called {
			t.Errorf("%s: v3Called = %v, want %v", tc.name, v3Called, tc.wantV3Called)
		}
		if !bytes.Equal(gotBody, tc.wantBody) {
			t.Errorf("%s: body = %q, want %q", tc.name, gotBody, tc.wantBody)
		}
		wantType := tc.v1Type
		if tc.wantV3Called {
			wantType = tc.v3Type
		}
		if gotType != wantType {
			t.Errorf("%s: Content-Type = %q, want %q", tc.name, gotType, wantType)
		}
	}
}

func TestDownloadMediaWithFallbackErrors(t *testing.T) {
	ctx := t.Context()
	mxc := id.ContentURI{Homeserver: "media2.example.net", FileID: "media-id-2"}

	if _, _, err := DownloadMediaWithFallback(ctx, nil, mxc); !errors.Is(err, ErrNilClient) {
		t.Fatalf("DownloadMediaWithFallback(nil) err = %v, want %v", err, ErrNilClient)
	}

	origMax := maxDownloadBytes
	t.Cleanup(func() {
		maxDownloadBytes = origMax
	})

	maxDownloadBytes = 4
	tooLargeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeRawResponse(t, w, http.StatusOK, "application/octet-stream", []byte("123456"))
	}))
	largeCli, err := NewClient(tooLargeSrv.URL, "@alice:media2.example.net", "tok-large", nil)
	if err != nil {
		tooLargeSrv.Close()
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, largeErr := DownloadMediaWithFallback(ctx, largeCli, mxc); !errors.Is(largeErr, ErrMediaTooLarge) {
		t.Errorf("oversized download err = %v, want %v", largeErr, ErrMediaTooLarge)
	}
	tooLargeSrv.Close()
	maxDownloadBytes = origMax

	legacySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeRawResponse(t, w, http.StatusOK, "image/webp", []byte("webp-ok"))
	}))
	parsedURL, parseErr := url.Parse(legacySrv.URL)
	if parseErr != nil {
		legacySrv.Close()
		t.Fatalf("parse server URL: %v", parseErr)
	}
	nilHTTPCli := &mautrix.Client{HomeserverURL: parsedURL}
	legacyBytes, legacyType, legacyErr := downloadLegacyMedia(ctx, nilHTTPCli, mxc)
	if legacyErr != nil || string(legacyBytes) != "webp-ok" || legacyType != "image/webp" {
		t.Fatalf("downloadLegacyMedia(nil Client) = %q, %q, %v", legacyBytes, legacyType, legacyErr)
	}
	legacySrv.Close()

	if _, _, closedErr := downloadLegacyMedia(ctx, nilHTTPCli, mxc); closedErr == nil {
		t.Errorf("expected downloadLegacyMedia error against closed server")
	}
}

func TestDownloadMediaFallbackHTTPErrors(t *testing.T) {
	ctx := t.Context()
	mxc := id.ContentURI{Homeserver: "media3.example.org", FileID: "media-id-3"}

	errCases := []struct {
		name        string
		v3ErrCode   string
		wantErrCode string
		v1Status    int
		v3Status    int
		wantStatus  int
	}{
		{
			name:       "v1 403 does not fall back",
			v1Status:   http.StatusForbidden,
			v3Status:   http.StatusOK,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "v3 returning 500 fails cleanly",
			v1Status:   http.StatusNotFound,
			v3Status:   http.StatusInternalServerError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:        "v3 returning Matrix 404 preserves RespError",
			v1Status:    http.StatusNotFound,
			v3Status:    http.StatusNotFound,
			v3ErrCode:   mautrix.MNotFound.ErrCode,
			wantStatus:  http.StatusNotFound,
			wantErrCode: mautrix.MNotFound.ErrCode,
		},
	}

	for _, tc := range errCases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/v1/media/") {
				writeMatrixError(t, w, tc.v1Status, "M_UNAVAILABLE", "denied")
				return
			}
			if tc.v3ErrCode != "" {
				writeMatrixError(t, w, tc.v3Status, tc.v3ErrCode, "missing legacy media")
				return
			}
			w.WriteHeader(tc.v3Status)
		}))

		cli, cliErr := NewClient(srv.URL, "@bob:media3.example.org", "tok-err", nil)
		if cliErr != nil {
			srv.Close()
			t.Fatalf("NewClient: %v", cliErr)
		}
		_, _, dlErr := DownloadMediaWithFallback(ctx, cli, mxc)
		srv.Close()
		if dlErr == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
			continue
		}
		if tc.wantStatus != 0 && !IsHTTPStatus(dlErr, tc.wantStatus) {
			t.Errorf("%s: expected HTTP status %d in error %v", tc.name, tc.wantStatus, dlErr)
		}
		if tc.wantErrCode != "" && !IsMatrixErrCode(dlErr, tc.wantErrCode) {
			t.Errorf("%s: expected errcode %s in error %v", tc.name, tc.wantErrCode, dlErr)
		}
	}
}

func TestHTTPHelpers(t *testing.T) {
	ctx := t.Context()

	if _, _, _, err := executeHTTPRequest(ctx, nil, http.MethodGet, "http://\x7f.example.com", http.NoBody, "", "", "bad-url"); err == nil {
		t.Errorf("expected build request error for control character URL")
	}

	readErrSentinel := errors.New("stream broken")
	closeErrSentinel := errors.New("close broken")

	if _, err := readBounded(failingReader{err: readErrSentinel}, 100); !errors.Is(err, readErrSentinel) {
		t.Errorf("readBounded err = %v, want %v", err, readErrSentinel)
	}

	failTransport := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: &failingCloseBody{
					reader:   strings.NewReader("ok"),
					closeErr: closeErrSentinel,
				},
			}, nil
		}),
	}
	if _, _, _, err := executeHTTPRequest(ctx, failTransport, http.MethodGet, "https://helper.example.com/test", http.NoBody, "", "", "op"); !errors.Is(err, closeErrSentinel) {
		t.Errorf("executeHTTPRequest close error = %v, want %v", err, closeErrSentinel)
	}

	mergeCases := []struct {
		readErr   error
		closeErr  error
		wantRead  bool
		wantClose bool
	}{
		{readErr: readErrSentinel, closeErr: closeErrSentinel, wantRead: true, wantClose: true},
		{readErr: readErrSentinel, wantRead: true},
		{closeErr: closeErrSentinel, wantClose: true},
		{},
	}

	for _, tc := range mergeCases {
		err := mergeReadCloseErr("op", tc.readErr, tc.closeErr)
		if !tc.wantRead && !tc.wantClose {
			if err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
			continue
		}
		if tc.wantRead && !errors.Is(err, tc.readErr) {
			t.Errorf("expected error to wrap %v, got %v", tc.readErr, err)
		}
		if tc.wantClose && !errors.Is(err, tc.closeErr) {
			t.Errorf("expected error to wrap %v, got %v", tc.closeErr, err)
		}
	}
}

func TestFetchBytes(t *testing.T) {
	ctx := t.Context()
	okTransport := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"errcode":"M_FORBIDDEN"}`)),
			}, nil
		}),
	}
	gotBody, gotStatus, fetchErr := FetchBytes(ctx, okTransport, "https://helper.example.com/_matrix/key/v2/server", "fetch key")
	if fetchErr != nil || gotStatus != http.StatusForbidden || string(gotBody) != `{"errcode":"M_FORBIDDEN"}` {
		t.Errorf("FetchBytes = (%q, %d, %v), want forbidden JSON body", gotBody, gotStatus, fetchErr)
	}
	if _, _, badFetchErr := FetchBytes(ctx, nil, "http://\x7f.example.com", "bad-fetch"); badFetchErr == nil {
		t.Errorf("expected FetchBytes error for invalid URL")
	}
}

func TestErrorPredicates(t *testing.T) {
	plainErr := errors.New("plain error")
	httpErrNoResp := mautrix.HTTPError{
		Response: &http.Response{StatusCode: http.StatusTeapot},
	}
	httpErrWithResp := mautrix.HTTPError{
		Response:  &http.Response{StatusCode: http.StatusForbidden},
		RespError: &mautrix.RespError{ErrCode: "M_TOO_LARGE"},
	}

	if IsHTTPStatus(plainErr, http.StatusNotFound) {
		t.Errorf("IsHTTPStatus(plainErr) = true, want false")
	}
	if !IsHTTPStatus(httpErrNoResp, http.StatusTeapot) || IsHTTPStatus(httpErrNoResp, http.StatusOK) {
		t.Errorf("unexpected IsHTTPStatus result on mautrix.HTTPError")
	}
	if IsMatrixErrCode(plainErr, "M_TOO_LARGE") || IsMatrixErrCode(httpErrNoResp, "M_TOO_LARGE") {
		t.Errorf("IsMatrixErrCode returned true without RespError")
	}
	if !IsMatrixErrCode(httpErrWithResp, "M_TOO_LARGE") || IsMatrixErrCode(httpErrWithResp, "M_UNKNOWN") {
		t.Errorf("unexpected IsMatrixErrCode result with RespError")
	}
}
