// Package dump manages the permission-hardened filesystem store for exported Synapse state and Tuwunel migration progress.
package dump

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

const (
	roomsDirName           = "rooms"
	mediaDirName           = "media"
	accountsDirName        = "accounts"
	manifestFileName       = "manifest_state.json"
	signingKeyTOMLFileName = "tuwunel-import-key.toml"
	localRoomsFileName     = "local_rooms.json"
	fedRoomsFileName       = "federated_rooms.json"
	identityFileName       = "identity.json"
	roomKeysFileName       = "room_keys.json"
	profileFileName        = "profile.json"
	trustGraphFileName     = "trust_graph.json"
	sessionFileName        = "session.json"
	sha256HexLength        = 64
	readOnlyFileMode       = 0o400
	atomicFileMode         = 0o600
	secureDirectoryMode    = 0o700
)

// Sentinel errors returned when reading, writing, or validating dump paths.
var (
	ErrUnsafePath       = errors.New("unsafe filesystem path segment")
	ErrInvalidMediaHash = errors.New("media digest must be a 64-character lowercase SHA-256 hex string")
	ErrMediaTooLarge    = errors.New("media payload exceeds maximum allowed size")
)

func defaultCreateTemp(dir, pattern string) (*os.File, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	return file, nil
}

func defaultFileWrite(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	return nil
}

func defaultFileChmod(file *os.File, mode os.FileMode) error {
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	return nil
}

func defaultFileSync(file *os.File) error {
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	return nil
}

func defaultReadFileBytes(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", cleanPath, err)
	}
	return data, nil
}

var (
	fileWrite     = defaultFileWrite
	fileChmod     = defaultFileChmod
	fileSync      = defaultFileSync
	readFileBytes = defaultReadFileBytes
)

func defaultWriteTempAndSync(file *os.File, data []byte) error {
	if err := fileWrite(file, data); err != nil {
		return err
	}
	if err := fileChmod(file, atomicFileMode); err != nil {
		return err
	}
	return fileSync(file)
}

func defaultRenameFile(oldpath, newpath string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", newpath, err)
	}
	return nil
}

func defaultReadSecureBytes(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	if err := validator.ValidateFileMode(cleanPath, 0o400, 0o600); err != nil {
		return nil, fmt.Errorf("validate file %q: %w", cleanPath, err)
	}
	return readFileBytes(cleanPath)
}

func defaultRemoveFile(path string) error {
	cleanPath := filepath.Clean(path)
	if err := os.Remove(cleanPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove file %q: %w", cleanPath, err)
	}
	return nil
}

func defaultJSONMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

var (
	createTempFile   = defaultCreateTemp
	writeTempAndSync = defaultWriteTempAndSync
	renameFile       = defaultRenameFile
	readSecureBytes  = defaultReadSecureBytes
	removeFile       = defaultRemoveFile
	jsonMarshal      = defaultJSONMarshal
	maxMediaBytes    = MaxMediaBytes
)

// Store manages atomic, mode-verified persistence within the migration dump directory.
type Store struct {
	root string
}

// Open initializes or verifies the 0700 dump directory tree before reading or writing state.
func Open(rootDir string) (*Store, error) {
	cleanRoot := filepath.Clean(strings.TrimSpace(rootDir))
	if cleanRoot == "" || cleanRoot == "." {
		return nil, fmt.Errorf("%w: empty dump directory", ErrUnsafePath)
	}

	requiredDirs := []string{
		cleanRoot,
		filepath.Join(cleanRoot, roomsDirName),
		filepath.Join(cleanRoot, mediaDirName),
		filepath.Join(cleanRoot, accountsDirName),
	}
	for _, dir := range requiredDirs {
		if err := validator.EnsureSecureDir(dir); err != nil {
			return nil, fmt.Errorf("ensure secure directory %q: %w", dir, err)
		}
	}

	return &Store{root: cleanRoot}, nil
}

// Root returns the cleaned root directory path of the store.
func (s *Store) Root() string {
	return s.root
}

// WriteManifest atomically persists manifest_state.json with 0600 permissions.
func (s *Store) WriteManifest(state *ManifestState) error {
	return s.writeJSON(filepath.Join(s.root, manifestFileName), state)
}

// ReadManifest loads manifest_state.json after verifying strict file permissions.
func (s *Store) ReadManifest() (*ManifestState, error) {
	var state ManifestState
	if err := s.readJSON(filepath.Join(s.root, manifestFileName), &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// SigningKeyTOMLPath returns the full path to the generated Tuwunel server signing key import drop-in.
func (s *Store) SigningKeyTOMLPath() string {
	return filepath.Join(s.root, signingKeyTOMLFileName)
}

// WriteSigningKeyTOML atomically writes the Tuwunel server signing key import drop-in with 0400 permissions.
func (s *Store) WriteSigningKeyTOML(data []byte) error {
	return writeAtomicWithMode(s.SigningKeyTOMLPath(), data, readOnlyFileMode)
}

// ValidateSigningKeyTOML verifies that tuwunel-import-key.toml exists as a regular file with 0400 or 0600 permissions.
func (s *Store) ValidateSigningKeyTOML() error {
	if err := validator.ValidateFileMode(s.SigningKeyTOMLPath(), readOnlyFileMode, atomicFileMode); err != nil {
		return fmt.Errorf("validate %s: %w", signingKeyTOMLFileName, err)
	}
	return nil
}

// WriteLocalRooms atomically persists deduplicated Category 3 and Category 4 rooms.
func (s *Store) WriteLocalRooms(data *LocalRoomsData) error {
	return s.writeJSON(filepath.Join(s.root, roomsDirName, localRoomsFileName), data)
}

// ReadLocalRooms loads deduplicated Category 3 and Category 4 rooms from disk.
func (s *Store) ReadLocalRooms() (*LocalRoomsData, error) {
	var data LocalRoomsData
	if err := s.readJSON(filepath.Join(s.root, roomsDirName, localRoomsFileName), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteFederatedRooms atomically persists Category 2 federated rooms for later rejoin.
func (s *Store) WriteFederatedRooms(data *FederatedRoomsData) error {
	return s.writeJSON(filepath.Join(s.root, roomsDirName, fedRoomsFileName), data)
}

// ReadFederatedRooms loads Category 2 federated rooms from disk.
func (s *Store) ReadFederatedRooms() (*FederatedRoomsData, error) {
	var data FederatedRoomsData
	if err := s.readJSON(filepath.Join(s.root, roomsDirName, fedRoomsFileName), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteIdentity persists decrypted cross-signing seeds, backup key, and SSSS metadata for an account.
func (s *Store) WriteIdentity(userID string, data *IdentityData) error {
	return s.writeAccountJSON(userID, identityFileName, data)
}

// ReadIdentity loads cryptographic identity material for an account.
func (s *Store) ReadIdentity(userID string) (*IdentityData, error) {
	var data IdentityData
	if err := s.readAccountJSON(userID, identityFileName, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteRoomKeys persists the filtered Megolm key backup payload for an account.
func (s *Store) WriteRoomKeys(userID string, data *RoomKeysData) error {
	return s.writeAccountJSON(userID, roomKeysFileName, data)
}

// ReadRoomKeys loads the exported Megolm key backup payload for an account.
func (s *Store) ReadRoomKeys(userID string) (*RoomKeysData, error) {
	var data RoomKeysData
	if err := s.readAccountJSON(userID, roomKeysFileName, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteProfile persists profile fields, direct room maps, ignore lists, and tags for an account.
func (s *Store) WriteProfile(userID string, data *ProfileData) error {
	return s.writeAccountJSON(userID, profileFileName, data)
}

// ReadProfile loads profile and client state metadata for an account.
func (s *Store) ReadProfile(userID string) (*ProfileData, error) {
	var data ProfileData
	if err := s.readAccountJSON(userID, profileFileName, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteTrustGraph persists the verified contacts snapshot signed by the account's user-signing key.
func (s *Store) WriteTrustGraph(userID string, data *TrustGraphData) error {
	return s.writeAccountJSON(userID, trustGraphFileName, data)
}

// ReadTrustGraph loads the cross-signing trust graph snapshot for an account.
func (s *Store) ReadTrustGraph(userID string) (*TrustGraphData, error) {
	var data TrustGraphData
	if err := s.readAccountJSON(userID, trustGraphFileName, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// WriteSession records an active temporary Tuwunel device session for cleanup.
func (s *Store) WriteSession(userID string, data *SessionData) error {
	return s.writeAccountJSON(userID, sessionFileName, data)
}

// ReadSession loads the active temporary Tuwunel session for cleanup.
func (s *Store) ReadSession(userID string) (*SessionData, error) {
	var data SessionData
	if err := s.readAccountJSON(userID, sessionFileName, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// RemoveSession deletes session.json once temporary migration devices have been logged out.
func (s *Store) RemoveSession(userID string) error {
	dir, err := s.accountDir(userID, false)
	if err != nil {
		return err
	}
	if dir == "" {
		return nil
	}
	return removeFile(filepath.Join(dir, sessionFileName))
}

// SaveMedia hashes binary payload content with SHA-256, stores it atomically under media/, and returns its reference.
func (s *Store) SaveMedia(originalMXC, contentType, filename string, data []byte) (*MediaRef, error) {
	if len(data) > maxMediaBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrMediaTooLarge, len(data))
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	target := filepath.Join(s.root, mediaDirName, digest)
	if err := writeAtomic(target, data); err != nil {
		return nil, err
	}
	return &MediaRef{
		OriginalMXC: originalMXC,
		SHA256:      digest,
		ContentType: contentType,
		FileName:    filename,
		Size:        int64(len(data)),
	}, nil
}

// ReadMedia verifies the SHA-256 path digest and reads binary media bytes under strict permissions.
func (s *Store) ReadMedia(digest string) ([]byte, error) {
	if err := validateSHA256Hex(digest); err != nil {
		return nil, err
	}
	return readSecureBytes(filepath.Join(s.root, mediaDirName, digest))
}

func validateSHA256Hex(digest string) error {
	if len(digest) != sha256HexLength {
		return ErrInvalidMediaHash
	}
	for i := range len(digest) {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ErrInvalidMediaHash
		}
	}
	return nil
}

func (s *Store) accountDir(userID string, create bool) (string, error) {
	if err := validator.ValidateUserID(userID); err != nil {
		return "", fmt.Errorf("validate account user ID: %w", err)
	}
	if strings.ContainsAny(userID, `/\`) || strings.Contains(userID, "..") {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, userID)
	}

	dir := filepath.Join(s.root, accountsDirName, userID)
	if create {
		if err := validator.EnsureSecureDir(dir); err != nil {
			return "", fmt.Errorf("ensure account dir %q: %w", dir, err)
		}
		return dir, nil
	}

	if err := validator.ValidateDirMode(dir, secureDirectoryMode); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("validate account dir %q: %w", dir, err)
	}
	return dir, nil
}

func (s *Store) writeAccountJSON(userID, filename string, payload any) error {
	dir, err := s.accountDir(userID, true)
	if err != nil {
		return err
	}
	return s.writeJSON(filepath.Join(dir, filename), payload)
}

func (s *Store) readAccountJSON(userID, filename string, dst any) error {
	dir, err := s.accountDir(userID, false)
	if err != nil {
		return err
	}
	if dir == "" {
		return fmt.Errorf("read %s for %s: %w", filename, userID, os.ErrNotExist)
	}
	return s.readJSON(filepath.Join(dir, filename), dst)
}

func (s *Store) writeJSON(target string, payload any) error {
	encoded, err := jsonMarshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %q: %w", filepath.Base(target), err)
	}
	return writeAtomic(target, encoded)
}

func (s *Store) readJSON(target string, dst any) error {
	raw, err := readSecureBytes(target)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("unmarshal %q: %w", filepath.Base(target), err)
	}
	return nil
}

func writeAtomic(targetPath string, data []byte) error {
	return writeAtomicWithMode(targetPath, data, atomicFileMode)
}

func writeAtomicWithMode(targetPath string, data []byte, finalMode os.FileMode) error {
	cleanPath := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanPath)
	if err := validator.ValidateDirMode(dir, secureDirectoryMode); err != nil {
		return fmt.Errorf("validate target dir %q: %w", dir, err)
	}

	tmp, err := createTempFile(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if syncErr := writeTempAndSync(tmp, data); syncErr != nil {
		return cleanupTempFile(tmp, tmpPath, syncErr)
	}

	if finalMode != atomicFileMode {
		if modErr := applyFinalModeAndSync(tmp, finalMode); modErr != nil {
			return cleanupTempFile(tmp, tmpPath, modErr)
		}
	}

	if closeErr := tmp.Close(); closeErr != nil {
		if remErr := removeFile(tmpPath); remErr != nil {
			return fmt.Errorf("close temp file: %w (remove temp failed: %w)", closeErr, remErr)
		}
		return fmt.Errorf("close temp file: %w", closeErr)
	}

	if renErr := renameFile(tmpPath, cleanPath); renErr != nil {
		if remErr := removeFile(tmpPath); remErr != nil {
			return fmt.Errorf("%w (remove temp failed: %w)", renErr, remErr)
		}
		return renErr
	}
	return nil
}

func applyFinalModeAndSync(file *os.File, mode os.FileMode) error {
	if err := fileChmod(file, mode); err != nil {
		return err
	}
	return fileSync(file)
}

func cleanupTempFile(tmp *os.File, tmpPath string, baseErr error) error {
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("%w (close also failed: %w)", baseErr, closeErr)
	}
	if remErr := removeFile(tmpPath); remErr != nil {
		return fmt.Errorf("%w (remove temp failed: %w)", baseErr, remErr)
	}
	return baseErr
}
