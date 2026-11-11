// Package matrix provides Matrix Client-Server helpers, pure-Go OlmMachine setup, UIA auth callbacks, and Tuwunel admin registration.
package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/matrix/sharedsecretmac"
)

// DefaultDeviceDisplayName identifies temporary device sessions created by the migration CLI.
const DefaultDeviceDisplayName = "synapse-tuwunel-migrator"

const (
	defaultHTTPTimeout    = 60 * time.Second
	defaultUserAgent      = "synapse-tuwunel-migration"
	adminRegisterPath     = "/_synapse/admin/v1/register"
	legacyMediaPathPrefix = "/_matrix/media/v3/download/"
	uiaFieldType          = "type"
)

// Sentinel errors returned by Matrix transport and authentication helpers.
var (
	ErrNilClient           = errors.New("matrix client must not be nil")
	ErrEmptySharedSecret   = errors.New("tuwunel_shared_secret must not be empty to register missing users")
	ErrWhoamiMismatch      = errors.New("access token belongs to unexpected Matrix user ID")
	ErrEmptyNonce          = errors.New("admin registration endpoint returned empty nonce")
	ErrAdminRegisterFailed = errors.New("admin shared-secret registration request failed")
	ErrMediaTooLarge       = errors.New("downloaded media exceeds maximum allowed size")
)

// RegisterResponse mirrors the JSON payload returned by /_synapse/admin/v1/register.
type RegisterResponse struct {
	AccessToken string `json:"access_token"`
	HomeServer  string `json:"home_server"`
	UserID      string `json:"user_id"`
	DeviceID    string `json:"device_id"`
}

type registerNonceResponse struct {
	Nonce string `json:"nonce"`
}

func defaultMautrixNewClient(homeserverURL string, userID id.UserID, accessToken string) (*mautrix.Client, error) {
	cli, err := mautrix.NewClient(homeserverURL, userID, accessToken)
	if err != nil {
		return nil, fmt.Errorf("create mautrix client: %w", err)
	}
	return cli, nil
}

func defaultMachineLoad(ctx context.Context, mach *crypto.OlmMachine) error {
	if err := mach.Load(ctx); err != nil {
		return fmt.Errorf("load olm machine: %w", err)
	}
	return nil
}

func defaultJSONMarshal(v any) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON payload: %w", err)
	}
	return encoded, nil
}

var (
	mautrixNewClient = defaultMautrixNewClient
	machineLoad      = defaultMachineLoad
	jsonMarshal      = defaultJSONMarshal
	maxDownloadBytes = int64(dump.MaxMediaBytes)
)

// NewClient initializes a mautrix Client with migration defaults and optional structured logging.
func NewClient(homeserverURL, userID, accessToken string, log *zerolog.Logger) (*mautrix.Client, error) {
	cleanURL := strings.TrimRight(strings.TrimSpace(homeserverURL), "/")
	cli, err := mautrixNewClient(cleanURL, id.UserID(userID), accessToken)
	if err != nil {
		return nil, err
	}
	cli.Client = &http.Client{Timeout: defaultHTTPTimeout}
	cli.UserAgent = defaultUserAgent
	if log != nil {
		cli.Log = *log
	} else {
		cli.Log = zerolog.Nop()
	}
	return cli, nil
}

// LoginPassword authenticates using m.login.password and returns a credentialed Client and login response.
func LoginPassword(ctx context.Context, homeserverURL, userID, password, deviceDisplayName string, log *zerolog.Logger) (*mautrix.Client, *mautrix.RespLogin, error) {
	cli, err := NewClient(homeserverURL, "", "", log)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(deviceDisplayName) == "" {
		deviceDisplayName = DefaultDeviceDisplayName
	}

	req := &mautrix.ReqLogin{
		Type: mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{
			Type: mautrix.IdentifierTypeUser,
			User: userID,
		},
		Password:                 password,
		InitialDeviceDisplayName: deviceDisplayName,
		StoreCredentials:         true,
	}
	resp, err := cli.Login(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("password login for %s: %w", userID, err)
	}
	return cli, resp, nil
}

// ConnectWithToken validates an existing bearer token via /whoami and returns a populated Client.
func ConnectWithToken(ctx context.Context, homeserverURL, expectedUserID, accessToken string, log *zerolog.Logger) (*mautrix.Client, *mautrix.RespWhoami, error) {
	cli, err := NewClient(homeserverURL, expectedUserID, accessToken, log)
	if err != nil {
		return nil, nil, err
	}
	resp, err := cli.Whoami(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("verify access token via whoami for %s: %w", expectedUserID, err)
	}
	if resp.UserID.String() != expectedUserID {
		return nil, nil, fmt.Errorf("%w: got %s, want %s", ErrWhoamiMismatch, resp.UserID, expectedUserID)
	}
	cli.DeviceID = resp.DeviceID
	return cli, resp, nil
}

// NewOlmMachine creates an in-memory pure-Go OlmMachine backed by goolm and MemoryStateStore.
func NewOlmMachine(ctx context.Context, cli *mautrix.Client, log *zerolog.Logger) (*crypto.OlmMachine, *mautrix.MemoryStateStore, error) {
	if cli == nil {
		return nil, nil, ErrNilClient
	}
	var machLog zerolog.Logger
	if log != nil {
		machLog = *log
	} else {
		machLog = zerolog.Nop()
	}

	cryptoStore := crypto.NewMemoryStore(nil)
	stateStore := &mautrix.MemoryStateStore{
		Registrations:     make(map[id.UserID]bool),
		Members:           make(map[id.RoomID]map[id.UserID]*event.MemberEventContent),
		MembersFetched:    make(map[id.RoomID]bool),
		PowerLevels:       make(map[id.RoomID]*event.PowerLevelsEventContent),
		Encryption:        make(map[id.RoomID]*event.EncryptionEventContent),
		Create:            make(map[id.RoomID]*event.Event),
		JoinRules:         make(map[id.RoomID]*event.JoinRulesEventContent),
		HistoryVisibility: make(map[id.RoomID]*event.HistoryVisibilityEventContent),
	}
	mach := crypto.NewOlmMachine(cli, &machLog, cryptoStore, stateStore)
	mach.DisableDecryptKeyFetching = true

	if err := machineLoad(ctx, mach); err != nil {
		return nil, nil, err
	}
	return mach, stateStore, nil
}

// PasswordUIACallback returns a headless UIA callback supporting m.login.password and m.login.dummy flows.
func PasswordUIACallback(userID id.UserID, password string) mautrix.UIACallback {
	return func(uiResp *mautrix.RespUserInteractive) any {
		if uiResp == nil {
			return nil
		}
		hasPassword := false
		hasDummy := false
		for _, flow := range uiResp.Flows {
			for _, stage := range flow.Stages {
				switch stage {
				case mautrix.AuthTypePassword:
					hasPassword = true
				case mautrix.AuthTypeDummy:
					hasDummy = true
				}
			}
		}

		if hasPassword {
			return map[string]any{
				uiaFieldType: mautrix.AuthTypePassword,
				"identifier": map[string]any{
					uiaFieldType: mautrix.IdentifierTypeUser,
					"user":       userID.String(),
				},
				"password": password,
				"session":  uiResp.Session,
			}
		}
		if hasDummy {
			return map[string]any{
				uiaFieldType: mautrix.AuthTypeDummy,
				"session":    uiResp.Session,
			}
		}
		return nil
	}
}

// RegisterSharedSecret provisions an account on Tuwunel using Synapse-compatible HMAC-SHA1 shared-secret registration.
func RegisterSharedSecret(ctx context.Context, homeserverURL, sharedSecret, username, password string, admin bool) (*RegisterResponse, error) {
	if sharedSecret == "" {
		return nil, ErrEmptySharedSecret
	}
	baseURL := strings.TrimRight(strings.TrimSpace(homeserverURL), "/")
	endpoint := baseURL + adminRegisterPath
	httpClient := &http.Client{Timeout: defaultHTTPTimeout}

	nonce, err := fetchRegisterNonce(ctx, httpClient, endpoint)
	if err != nil {
		return nil, err
	}

	mac := sharedsecretmac.Compute(sharedSecret, nonce, username, password, admin)
	payload := map[string]any{
		"nonce":    nonce,
		"username": username,
		"password": password,
		"admin":    admin,
		"mac":      mac,
	}
	bodyBytes, err := jsonMarshal(payload)
	if err != nil {
		return nil, err
	}

	respBody, statusCode, _, err := executeHTTPRequest(
		ctx,
		httpClient,
		http.MethodPost,
		endpoint,
		bytes.NewReader(bodyBytes),
		"application/json",
		"",
		"admin register submit",
	)
	if err != nil {
		return nil, err
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: status %d: %s", ErrAdminRegisterFailed, statusCode, strings.TrimSpace(string(respBody)))
	}

	var out RegisterResponse
	if unmarshalErr := json.Unmarshal(respBody, &out); unmarshalErr != nil {
		return nil, fmt.Errorf("decode admin register response: %w", unmarshalErr)
	}
	return &out, nil
}

func fetchRegisterNonce(ctx context.Context, httpClient *http.Client, endpoint string) (string, error) {
	body, statusCode, _, err := executeHTTPRequest(
		ctx,
		httpClient,
		http.MethodGet,
		endpoint,
		http.NoBody,
		"",
		"",
		"fetch registration nonce",
	)
	if err != nil {
		return "", err
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("%w: nonce status %d: %s", ErrAdminRegisterFailed, statusCode, strings.TrimSpace(string(body)))
	}

	var decoded registerNonceResponse
	if unmarshalErr := json.Unmarshal(body, &decoded); unmarshalErr != nil {
		return "", fmt.Errorf("decode nonce JSON: %w", unmarshalErr)
	}
	if decoded.Nonce == "" {
		return "", ErrEmptyNonce
	}
	return decoded.Nonce, nil
}

// DownloadMediaWithFallback downloads Matrix media using authenticated v1 endpoints first, falling back to v3 media routes.
func DownloadMediaWithFallback(ctx context.Context, cli *mautrix.Client, mxc id.ContentURI) (data []byte, contentType string, retErr error) {
	if cli == nil {
		return nil, "", ErrNilClient
	}
	resp, dlErr := cli.Download(ctx, mxc)
	if dlErr == nil {
		bodyData, readErr := readBounded(resp.Body, maxDownloadBytes)
		closeErr := resp.Body.Close()
		if mergeErr := mergeReadCloseErr("read downloaded media "+mxc.String(), readErr, closeErr); mergeErr != nil {
			return nil, "", mergeErr
		}
		return bodyData, resp.Header.Get("Content-Type"), nil
	}

	if !IsHTTPStatus(dlErr, http.StatusNotFound) && !IsMatrixErrCode(dlErr, mautrix.MUnrecognized.ErrCode) {
		return nil, "", fmt.Errorf("download media %s: %w", mxc.String(), dlErr)
	}

	return downloadLegacyMedia(ctx, cli, mxc)
}

func downloadLegacyMedia(ctx context.Context, cli *mautrix.Client, mxc id.ContentURI) (data []byte, contentType string, retErr error) {
	escapedHS := url.PathEscape(mxc.Homeserver)
	escapedID := url.PathEscape(mxc.FileID)
	legacyURL := strings.TrimRight(cli.HomeserverURL.String(), "/") + legacyMediaPathPrefix + escapedHS + "/" + escapedID

	bodyData, statusCode, headers, reqErr := executeHTTPRequest(
		ctx,
		cli.Client,
		http.MethodGet,
		legacyURL,
		http.NoBody,
		"",
		cli.AccessToken,
		"download legacy media "+mxc.String(),
	)
	if reqErr != nil {
		return nil, "", reqErr
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		var respErr mautrix.RespError
		var parsedRespErr *mautrix.RespError
		if json.Unmarshal(bodyData, &respErr) == nil && respErr.ErrCode != "" {
			parsedRespErr = &respErr
		}
		return nil, "", mautrix.HTTPError{
			Response:     &http.Response{StatusCode: statusCode},
			ResponseBody: strings.TrimSpace(string(bodyData)),
			RespError:    parsedRespErr,
			Message:      fmt.Sprintf("legacy media %s returned HTTP %d", mxc.String(), statusCode),
		}
	}
	return bodyData, headers.Get("Content-Type"), nil
}

func executeHTTPRequest(ctx context.Context, httpClient *http.Client, method, targetURL string, body io.Reader, contentType, bearerToken, op string) (respBody []byte, statusCode int, respHeader http.Header, retErr error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	req, reqErr := http.NewRequestWithContext(ctx, method, targetURL, body)
	if reqErr != nil {
		return nil, 0, nil, fmt.Errorf("%s: build request: %w", op, reqErr)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, doErr := httpClient.Do(req)
	if doErr != nil {
		return nil, 0, nil, fmt.Errorf("%s: execute request: %w", op, doErr)
	}
	readData, readErr := readBounded(resp.Body, maxDownloadBytes)
	closeErr := resp.Body.Close()
	if mergeErr := mergeReadCloseErr(op, readErr, closeErr); mergeErr != nil {
		return nil, 0, nil, mergeErr
	}
	return readData, resp.StatusCode, resp.Header, nil
}

func readBounded(body io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(body, maxBytes+1)
	data, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, fmt.Errorf("read response body: %w", readErr)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: exceeded %d bytes", ErrMediaTooLarge, maxBytes)
	}
	return data, nil
}

// FetchBytes executes a bounded HTTP GET request and returns the response payload and status code.
func FetchBytes(ctx context.Context, httpClient *http.Client, targetURL, op string) (respBody []byte, statusCode int, retErr error) {
	respBody, statusCode, _, retErr = executeHTTPRequest(ctx, httpClient, http.MethodGet, targetURL, http.NoBody, "", "", op)
	if retErr != nil {
		return nil, 0, retErr
	}
	return respBody, statusCode, nil
}

func mergeReadCloseErr(op string, readErr, closeErr error) error {
	if readErr != nil {
		if closeErr != nil {
			return fmt.Errorf("%s: %w (close failed: %w)", op, readErr, closeErr)
		}
		return fmt.Errorf("%s: %w", op, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%s: close response body: %w", op, closeErr)
	}
	return nil
}

// IsHTTPStatus reports whether err wraps a mautrix.HTTPError with the given HTTP status code.
func IsHTTPStatus(err error, status int) bool {
	var httpErr mautrix.HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.IsStatus(status)
}

// IsMatrixErrCode reports whether err wraps a mautrix Matrix error carrying the expected errcode string.
func IsMatrixErrCode(err error, errCode string) bool {
	var httpErr mautrix.HTTPError
	if !errors.As(err, &httpErr) || httpErr.RespError == nil {
		return false
	}
	return httpErr.RespError.ErrCode == errCode
}
