// Package validator enforces Matrix identifier formats, URL sanity, and strict POSIX DAC permissions.
package validator

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

func defaultLstat(name string) (os.FileInfo, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("lstat %q: %w", name, err)
	}
	return info, nil
}

func defaultMkdirAll(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("create directory %q: %w", path, err)
	}
	return nil
}

func defaultAbsPath(path string) (string, error) {
	abs, err := filepathAbs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path %q: %w", path, err)
	}
	return abs, nil
}

func defaultEvalSymlinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("evaluate symlinks for %q: %w", path, err)
	}
	return resolved, nil
}

func defaultRelPath(basepath, targpath string) (string, error) {
	rel, err := filepath.Rel(basepath, targpath)
	if err != nil {
		return "", fmt.Errorf("compute relative path from %q to %q: %w", basepath, targpath, err)
	}
	return rel, nil
}

var (
	lstatFile    = defaultLstat
	mkdirAll     = defaultMkdirAll
	filepathAbs  = filepath.Abs
	absPath      = defaultAbsPath
	evalSymlinks = defaultEvalSymlinks
	relPath      = defaultRelPath
	goOS         = runtime.GOOS
)

const (
	localhost    = "localhost"
	windowsOS    = "windows"
	maxUserIDLen = 255
)

// Validation sentinel errors returned by the validator package.
var (
	ErrInvalidURL           = errors.New("invalid HTTP/HTTPS URL format")
	ErrURLCredentials       = errors.New("URL must not contain embedded credentials")
	ErrInvalidPort          = errors.New("port must be between 1 and 65535")
	ErrInvalidDomain        = errors.New("invalid domain structure")
	ErrInvalidRoomID        = errors.New("invalid Matrix room ID format")
	ErrInvalidUserID        = errors.New("invalid Matrix user ID format")
	ErrUserDomainMismatch   = errors.New("user ID server domain does not match configured server_name")
	ErrInsecurePermission   = errors.New("insecure file or directory permissions")
	ErrNotRegularFile       = errors.New("expected a regular non-symlink file")
	ErrNotDirectory         = errors.New("expected a non-symlink directory")
	ErrPathOutsideWorkspace = errors.New("path escapes migration working directory")
)

// ValidateDomain ensures the string conforms to ASCII DNS host rules permitted for Matrix server names.
func ValidateDomain(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == localhost {
		return nil
	}

	domain = strings.TrimSuffix(domain, ".")
	if len(domain) < 3 || len(domain) > 253 {
		return ErrInvalidDomain
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ErrInvalidDomain
	}

	for _, part := range parts {
		if err := validateDomainLabel(part); err != nil {
			return err
		}
	}

	if isNumericLabel(parts[len(parts)-1]) {
		return ErrInvalidDomain
	}

	return nil
}

func validateDomainLabel(part string) error {
	pl := len(part)
	if pl < 1 || pl > 63 {
		return ErrInvalidDomain
	}
	if part[0] == '-' || part[pl-1] == '-' {
		return ErrInvalidDomain
	}
	for i := range len(part) {
		c := part[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return ErrInvalidDomain
		}
	}
	return nil
}

func isNumericLabel(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ValidateServerName checks that a Matrix server_name is a valid domain or IP address with an optional port.
func ValidateServerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrInvalidDomain
	}

	host, portStr, err := net.SplitHostPort(name)
	if err != nil {
		host = name
	} else {
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port < 1 || port > 65535 {
			return ErrInvalidPort
		}
	}

	cleanHost := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if net.ParseIP(cleanHost) != nil {
		return nil
	}

	return ValidateDomain(host)
}

// ValidateHTTPURL requires an explicit HTTP or HTTPS URL without embedded userinfo credentials.
func ValidateHTTPURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return ErrInvalidURL
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" {
		return ErrInvalidURL
	}
	if parsed.User != nil {
		return ErrURLCredentials
	}
	return ValidateServerName(parsed.Host)
}

// ValidateUserID verifies that a Matrix user ID conforms to @localpart:domain syntax.
func ValidateUserID(userID string) error {
	if len(userID) > maxUserIDLen || !strings.HasPrefix(userID, "@") {
		return ErrInvalidUserID
	}
	body := userID[1:]
	parts := strings.SplitN(body, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !isValidUserLocalpart(parts[0]) {
		return ErrInvalidUserID
	}
	if err := ValidateServerName(parts[1]); err != nil {
		return ErrInvalidUserID
	}
	return nil
}

// ValidateUserIDForServer verifies that userID is syntactically valid and belongs to expectedServer.
func ValidateUserIDForServer(userID, expectedServer string) error {
	if err := ValidateUserID(userID); err != nil {
		return err
	}
	parts := strings.SplitN(userID[1:], ":", 2)
	if parts[1] != expectedServer {
		return fmt.Errorf("%w: got %q, want %q", ErrUserDomainMismatch, parts[1], expectedServer)
	}
	return nil
}

func isValidUserLocalpart(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '=' || c == '/' || c == '+' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateRoomID checks that a Matrix room ID conforms to !opaque_id:server_name syntax.
func ValidateRoomID(roomID string) error {
	if !strings.HasPrefix(roomID, "!") {
		return ErrInvalidRoomID
	}
	body := roomID[1:]
	if body == "" {
		return ErrInvalidRoomID
	}
	parts := strings.SplitN(body, ":", 2)
	if parts[0] == "" || !isValidRoomLocalpart(parts[0]) {
		return ErrInvalidRoomID
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return ErrInvalidRoomID
		}
		if err := ValidateServerName(parts[1]); err != nil {
			return ErrInvalidRoomID
		}
	}
	return nil
}

func isValidRoomLocalpart(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '=' || c == '/' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateFileMode ensures a sensitive configuration or dump file is a regular non-symlink file with strict DAC permissions.
func ValidateFileMode(filePath string, allowed ...os.FileMode) error {
	info, err := lstatFile(filePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegularFile, filePath)
	}
	if goOS == windowsOS {
		return nil
	}
	if len(allowed) == 0 {
		allowed = []os.FileMode{0o600}
	}
	perm := info.Mode().Perm()
	if !slices.Contains(allowed, perm) {
		return fmt.Errorf("%w: %s has mode %04o", ErrInsecurePermission, filePath, perm)
	}
	return nil
}

// ValidateDirMode ensures a directory is not a symlink and strictly enforces the expected DAC mode.
func ValidateDirMode(dirPath string, expectedPerm os.FileMode) error {
	info, err := lstatFile(dirPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrNotDirectory, dirPath)
	}
	if goOS == windowsOS {
		return nil
	}
	perm := info.Mode().Perm()
	if perm != expectedPerm {
		return fmt.Errorf("%w: %s has mode %04o, expected %04o", ErrInsecurePermission, dirPath, perm, expectedPerm)
	}
	return nil
}

// EnsureSecureDir creates a missing directory with 0700 permissions or verifies an existing directory matches 0700.
func EnsureSecureDir(dirPath string) error {
	err := ValidateDirMode(dirPath, 0o700)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if mkErr := mkdirAll(dirPath, 0o700); mkErr != nil {
		return mkErr
	}
	return ValidateDirMode(dirPath, 0o700)
}

// ValidateWorkspaceDir ensures the migration workspace is a non-symlink 0700 directory and returns its canonical path.
func ValidateWorkspaceDir(dir string) (string, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty workspace directory", ErrNotDirectory)
	}
	absDir, err := absPath(trimmed)
	if err != nil {
		return "", err
	}
	if modeErr := ValidateDirMode(absDir, 0o700); modeErr != nil {
		return "", modeErr
	}
	canon, err := evalSymlinks(absDir)
	if err != nil {
		return "", err
	}
	return canon, nil
}

// ConfinePath resolves targetPath relative to workspaceDir and rejects directory traversal or symlink escapes.
func ConfinePath(workspaceDir, targetPath string, allowWorkspaceRoot bool) (string, error) {
	canonWorkspace, err := ValidateWorkspaceDir(workspaceDir)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(targetPath)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty target path", ErrPathOutsideWorkspace)
	}
	candidate := trimmed
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(canonWorkspace, candidate)
	}
	resolved, err := resolvePathSymlinks(candidate)
	if err != nil {
		return "", err
	}
	rel, err := relPath(canonWorkspace, resolved)
	if err != nil {
		return "", err
	}
	if isOutsideWorkspace(rel, allowWorkspaceRoot) {
		return "", fmt.Errorf("%w: %q resolves outside %q", ErrPathOutsideWorkspace, targetPath, canonWorkspace)
	}
	return resolved, nil
}

func resolvePathSymlinks(target string) (string, error) {
	curr := filepath.Clean(target)
	var tail []string
	for {
		_, err := lstatFile(curr)
		if err == nil {
			canon, evalErr := evalSymlinks(curr)
			if evalErr != nil {
				return "", evalErr
			}
			for _, seg := range slices.Backward(tail) {
				canon = filepath.Join(canon, seg)
			}
			return canon, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return "", err
		}
		tail = append(tail, filepath.Base(curr))
		curr = parent
	}
}

func isOutsideWorkspace(rel string, allowWorkspaceRoot bool) bool {
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	return rel == "." && !allowWorkspaceRoot
}
