package validator

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeFileInfo struct {
	mode os.FileMode
	dir  bool
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.dir }
func (f fakeFileInfo) Sys() any           { return nil }

func TestValidateDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{name: "localhost", domain: "localhost", wantErr: false},
		{name: "example dot com", domain: "example.com", wantErr: false},
		{name: "subdomain", domain: "matrix.sub.example.org", wantErr: false},
		{name: "trailing dot", domain: "example.net.", wantErr: false},
		{name: "punycode", domain: "xn--e1afmkfd.example", wantErr: false},
		{name: "too short", domain: "a.", wantErr: true},
		{name: "too long", domain: strings.Repeat("a.", 128) + "long.example", wantErr: true},
		{name: "single label", domain: "intranet", wantErr: true},
		{name: "numeric tld", domain: "host.123", wantErr: true},
		{name: "empty label", domain: "bad..sub.example", wantErr: true},
		{name: "label too long", domain: strings.Repeat("a", 64) + ".lbl.example", wantErr: true},
		{name: "leading hyphen", domain: "-bad.example.net", wantErr: true},
		{name: "trailing hyphen", domain: "bad-.example.org", wantErr: true},
		{name: "invalid chars", domain: "bad_host.test.example", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDomain(tc.domain)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDomain(%q) error = %v, wantErr %v", tc.domain, err, tc.wantErr)
			}
		})
	}
}

func TestValidateServerName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		server  string
		wantErr bool
	}{
		{name: "domain", server: "srv.example.com", wantErr: false},
		{name: "domain with port", server: "matrix.example.net:8448", wantErr: false},
		{name: "ipv4", server: "127.0.0.1", wantErr: false},
		{name: "ipv6 with port", server: "[::1]:8448", wantErr: false},
		{name: "empty", server: "", wantErr: true},
		{name: "port zero", server: "zero.example.org:0", wantErr: true},
		{name: "port overflow", server: "over.example.net:65536", wantErr: true},
		{name: "port non numeric", server: "nan.example:abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateServerName(tc.server)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateServerName(%q) error = %v, wantErr %v", tc.server, err, tc.wantErr)
			}
		})
	}
}

func TestValidateHTTPURL(t *testing.T) {
	t.Parallel()

	credURL := (&url.URL{
		Scheme: "https",
		User:   url.User("alice"),
		Host:   "cred.example.net",
	}).String()

	tests := []struct {
		wantErr error
		name    string
		raw     string
	}{
		{name: "https", raw: "https://synapse.example.com"},
		{name: "http with port", raw: "http://127.0.0.1:8008"},
		{name: "missing scheme", raw: "tuwunel.example.org", wantErr: ErrInvalidURL},
		{name: "ftp scheme", raw: "ftp://files.example.net", wantErr: ErrInvalidURL},
		{name: "empty host", raw: "https:///path", wantErr: ErrInvalidURL},
		{name: "embedded credentials", raw: credURL, wantErr: ErrURLCredentials},
		{name: "bad port", raw: "https://badport.example:99999", wantErr: ErrInvalidPort},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHTTPURL(tc.raw)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateUserIDAndServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr    error
		name       string
		userID     string
		serverName string
	}{
		{name: "valid user", userID: "@alice:alpha.example.com", serverName: "alpha.example.com"},
		{name: "valid special localpart", userID: "@a.b_c=d/e+f-g:sub.example.org", serverName: "sub.example.org"},
		{name: "domain mismatch", userID: "@alice:beta.example.net", serverName: "alpha.example.net", wantErr: ErrUserDomainMismatch},
		{name: "missing at", userID: "alice:gamma.example.org", serverName: "gamma.example.org", wantErr: ErrInvalidUserID},
		{name: "missing colon", userID: "@alice", serverName: "delta.example", wantErr: ErrInvalidUserID},
		{name: "empty localpart", userID: "@:epsilon.example", serverName: "epsilon.example", wantErr: ErrInvalidUserID},
		{name: "invalid localpart char", userID: "@alice!:zeta.example", serverName: "zeta.example", wantErr: ErrInvalidUserID},
		{name: "invalid domain", userID: "@alice:bad", serverName: "bad", wantErr: ErrInvalidUserID},
		{name: "too long", userID: "@" + strings.Repeat("a", 250) + ":long.example", serverName: "long.example", wantErr: ErrInvalidUserID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateUserIDForServer(tc.userID, tc.serverName)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateRoomID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		roomID  string
		wantErr bool
	}{
		{name: "valid room", roomID: "!abcDEF123_=-/:room.example.com", wantErr: false},
		{name: "opaque only v12", roomID: "!opaque_room_id_123", wantErr: false},
		{name: "missing bang", roomID: "abc:room.example.net", wantErr: true},
		{name: "empty after bang", roomID: "!", wantErr: true},
		{name: "empty localpart", roomID: "!:room.example.org", wantErr: true},
		{name: "invalid localpart", roomID: "!bad*id:bad.example", wantErr: true},
		{name: "empty domain", roomID: "!abc:", wantErr: true},
		{name: "invalid domain", roomID: "!abc:bad", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRoomID(tc.roomID)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateRoomID(%q) error = %v, wantErr %v", tc.roomID, err, tc.wantErr)
			}
		})
	}
}

func TestValidateFileMode(t *testing.T) {
	tmpDir := t.TempDir()
	secureDir := filepath.Join(tmpDir, "secure")
	if err := EnsureSecureDir(secureDir); err != nil {
		t.Fatalf("EnsureSecureDir failed: %v", err)
	}
	file600 := filepath.Join(secureDir, "cfg.json")
	if err := os.WriteFile(file600, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file400 := filepath.Join(secureDir, "ro.json")
	if err := os.WriteFile(file400, []byte("{}"), 0o400); err != nil {
		t.Fatalf("write file: %v", err)
	}
	linkPath := filepath.Join(secureDir, "link.json")
	if err := os.Symlink(file600, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	realTests := []struct {
		wantErr error
		name    string
		path    string
		allowed []os.FileMode
	}{
		{name: "default 0600 ok", path: file600},
		{name: "0400 allowed", path: file400, allowed: []os.FileMode{0o400, 0o600}},
		{name: "symlink rejected", path: linkPath, wantErr: ErrNotRegularFile},
		{name: "directory rejected", path: secureDir, wantErr: ErrNotRegularFile},
		{name: "missing file", path: filepath.Join(secureDir, "missing.json"), wantErr: os.ErrNotExist},
	}

	for _, tc := range realTests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFileMode(tc.path, tc.allowed...)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}

	origLstat := lstatFile
	origOS := goOS
	t.Cleanup(func() {
		lstatFile = origLstat
		goOS = origOS
	})

	lstatFile = func(_ string) (os.FileInfo, error) {
		return fakeFileInfo{mode: 0o644}, nil
	}
	if err := ValidateFileMode("/fake/open.json", 0o400, 0o600); !errors.Is(err, ErrInsecurePermission) {
		t.Fatalf("expected ErrInsecurePermission, got %v", err)
	}

	goOS = windowsOS
	if err := ValidateFileMode("/fake/win.json", 0o600); err != nil {
		t.Fatalf("expected windows bypass, got %v", err)
	}
}

func TestValidateDirModeAndEnsure(t *testing.T) {
	tmpDir := t.TempDir()
	secureDir := filepath.Join(tmpDir, "secure_dir")
	if err := EnsureSecureDir(secureDir); err != nil {
		t.Fatalf("EnsureSecureDir failed: %v", err)
	}
	if err := EnsureSecureDir(secureDir); err != nil {
		t.Fatalf("EnsureSecureDir idempotent check failed: %v", err)
	}

	dirLink := filepath.Join(tmpDir, "dir_link")
	if err := os.Symlink(secureDir, dirLink); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	regularFile := filepath.Join(secureDir, "file.txt")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := EnsureSecureDir(dirLink); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("expected ErrNotDirectory for symlink, got %v", err)
	}
	if err := EnsureSecureDir(regularFile); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("expected ErrNotDirectory for regular file, got %v", err)
	}

	blockedParent := filepath.Join(regularFile, "child")
	if err := defaultMkdirAll(blockedParent, 0o700); err == nil {
		t.Fatal("expected defaultMkdirAll error under regular file")
	}

	origLstat := lstatFile
	origMkdir := mkdirAll
	origOS := goOS
	t.Cleanup(func() {
		lstatFile = origLstat
		mkdirAll = origMkdir
		goOS = origOS
	})

	lstatFile = func(_ string) (os.FileInfo, error) {
		return fakeFileInfo{mode: os.ModeDir | 0o755, dir: true}, nil
	}
	if err := EnsureSecureDir("/fake/open_dir"); !errors.Is(err, ErrInsecurePermission) {
		t.Fatalf("expected ErrInsecurePermission, got %v", err)
	}

	goOS = windowsOS
	if err := ValidateDirMode("/fake/win_dir", 0o700); err != nil {
		t.Fatalf("expected windows dir bypass, got %v", err)
	}

	goOS = "linux"
	lstatFile = origLstat
	mkdirAll = func(_ string, _ os.FileMode) error {
		return errors.New("mkdir failed")
	}
	if err := EnsureSecureDir(filepath.Join(tmpDir, "newdir")); err == nil {
		t.Fatal("expected mkdir failure")
	}
}

type confinementFixtures struct {
	workDir     string
	canonWork   string
	openDir     string
	stateFile   string
	outsideFile string
	workLink    string
}

func prepareConfinementFixtures(t *testing.T) confinementFixtures {
	t.Helper()
	base := t.TempDir()
	workDir := filepath.Join(base, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	openDir := filepath.Join(base, "open")
	if err := os.MkdirAll(openDir, 0o700); err != nil {
		t.Fatalf("mkdir open: %v", err)
	}
	if err := os.Chmod(openDir, 0o400); err != nil {
		t.Fatalf("chmod open: %v", err)
	}
	outsideDir := filepath.Join(base, "outside")
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideFile := filepath.Join(outsideDir, "secret.json")
	if err := os.WriteFile(outsideFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	stateFile := filepath.Join(workDir, "state.json")
	if err := os.WriteFile(stateFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}
	plainFile := filepath.Join(workDir, "plain.txt")
	if err := os.WriteFile(plainFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	escapeLink := filepath.Join(workDir, "escape-dir")
	if err := os.Symlink(outsideDir, escapeLink); err != nil {
		t.Fatalf("symlink escape: %v", err)
	}
	brokenLink := filepath.Join(workDir, "broken-link")
	if err := os.Symlink(filepath.Join(outsideDir, "missing"), brokenLink); err != nil {
		t.Fatalf("symlink broken: %v", err)
	}
	workLink := filepath.Join(base, "work-link")
	if err := os.Symlink(workDir, workLink); err != nil {
		t.Fatalf("symlink work: %v", err)
	}
	canonWork, err := ValidateWorkspaceDir(workDir)
	if err != nil {
		t.Fatalf("ValidateWorkspaceDir(%q) err = %v", workDir, err)
	}
	return confinementFixtures{
		workDir:     workDir,
		canonWork:   canonWork,
		openDir:     openDir,
		stateFile:   stateFile,
		outsideFile: outsideFile,
		workLink:    workLink,
	}
}

func TestValidateWorkspaceAndConfinePath(t *testing.T) {
	fx := prepareConfinementFixtures(t)

	tests := []struct {
		wantErr   error
		name      string
		workspace string
		target    string
		wantRel   string
		allowRoot bool
		anyErr    bool
	}{
		{
			name:      "relative file inside workspace",
			workspace: fx.workDir,
			target:    "migration.json",
			wantRel:   "migration.json",
		},
		{
			name:      "absolute un-canonicalized path inside workspace",
			workspace: fx.workDir,
			target:    fx.stateFile,
			wantRel:   "state.json",
		},
		{
			name:      "non-existent nested data directory inside workspace",
			workspace: fx.workDir,
			target:    filepath.Join("dump", "sub"),
			wantRel:   filepath.Join("dump", "sub"),
		},
		{
			name:      "workspace root allowed explicitly",
			workspace: fx.workDir,
			target:    ".",
			allowRoot: true,
			wantRel:   ".",
		},
		{
			name:      "workspace root disallowed when child required",
			workspace: fx.workDir,
			target:    ".",
			allowRoot: false,
			wantErr:   ErrPathOutsideWorkspace,
		},
		{
			name:      "empty target rejected",
			workspace: fx.workDir,
			target:    "   ",
			wantErr:   ErrPathOutsideWorkspace,
		},
		{
			name:      "dotdot traversal rejected",
			workspace: fx.workDir,
			target:    filepath.Join("..", "outside", "secret.json"),
			wantErr:   ErrPathOutsideWorkspace,
		},
		{
			name:      "absolute outside target rejected",
			workspace: fx.workDir,
			target:    fx.outsideFile,
			wantErr:   ErrPathOutsideWorkspace,
		},
		{
			name:      "symlink escape rejected",
			workspace: fx.workDir,
			target:    filepath.Join("escape-dir", "child"),
			wantErr:   ErrPathOutsideWorkspace,
		},
		{
			name:      "broken symlink rejected",
			workspace: fx.workDir,
			target:    "broken-link",
			wantErr:   os.ErrNotExist,
		},
		{
			name:      "child under regular file fails lstat",
			workspace: fx.workDir,
			target:    filepath.Join("plain.txt", "nested"),
			anyErr:    true,
		},
		{
			name:      "empty workspace rejected",
			workspace: " ",
			target:    "manifest.json",
			wantErr:   ErrNotDirectory,
		},
		{
			name:      "symlink workspace rejected",
			workspace: fx.workLink,
			target:    "settings.json",
			wantErr:   ErrNotDirectory,
		},
		{
			name:      "0400 workspace rejected",
			workspace: fx.openDir,
			target:    "account.json",
			wantErr:   ErrInsecurePermission,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, cErr := ConfinePath(tc.workspace, tc.target, tc.allowRoot)
			if tc.anyErr {
				if cErr == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if tc.wantErr != nil {
				if !errors.Is(cErr, tc.wantErr) {
					t.Fatalf("ConfinePath err = %v, want %v", cErr, tc.wantErr)
				}
				return
			}
			if cErr != nil {
				t.Fatalf("unexpected error: %v", cErr)
			}
			wantPath := filepath.Clean(filepath.Join(fx.canonWork, tc.wantRel))
			if got != wantPath {
				t.Fatalf("ConfinePath = %q, want %q", got, wantPath)
			}
		})
	}
}

func TestWorkspaceAndConfineHookErrors(t *testing.T) {
	base := t.TempDir()
	workDir := filepath.Join(base, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}

	origFilepathAbs := filepathAbs
	origAbs := absPath
	origEval := evalSymlinks
	origRel := relPath
	origLstat := lstatFile
	t.Cleanup(func() {
		filepathAbs = origFilepathAbs
		absPath = origAbs
		evalSymlinks = origEval
		relPath = origRel
		lstatFile = origLstat
	})

	absSentinel := errors.New("filepath abs failed")
	filepathAbs = func(string) (string, error) {
		return "", absSentinel
	}
	if _, err := defaultAbsPath("relative-work"); !errors.Is(err, absSentinel) {
		t.Fatalf("defaultAbsPath err = %v, want %v", err, absSentinel)
	}
	filepathAbs = origFilepathAbs

	if _, err := defaultEvalSymlinks(filepath.Join(base, "does-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaultEvalSymlinks missing err = %v", err)
	}
	if _, err := defaultRelPath(workDir, "relative-b"); err == nil {
		t.Fatal("expected defaultRelPath error on mixed abs/rel")
	}

	hookCases := []struct {
		setup func()
		fn    func() error
		name  string
	}{
		{
			name: "absPath error in ValidateWorkspaceDir",
			setup: func() {
				absPath = func(string) (string, error) { return "", errors.New("abs failed") }
			},
			fn: func() error { _, e := ValidateWorkspaceDir(workDir); return e },
		},
		{
			name: "evalSymlinks error in ValidateWorkspaceDir",
			setup: func() {
				absPath = origAbs
				evalSymlinks = func(string) (string, error) { return "", errors.New("eval failed") }
			},
			fn: func() error { _, e := ValidateWorkspaceDir(workDir); return e },
		},
		{
			name: "relPath error in ConfinePath",
			setup: func() {
				absPath = origAbs
				evalSymlinks = origEval
				relPath = func(string, string) (string, error) { return "", errors.New("rel failed") }
			},
			fn: func() error { _, e := ConfinePath(workDir, "hook.json", false); return e },
		},
		{
			name: "root reached in resolvePathSymlinks",
			setup: func() {
				absPath = origAbs
				evalSymlinks = origEval
				relPath = origRel
				lstatFile = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			},
			fn: func() error { _, e := resolvePathSymlinks(string(filepath.Separator)); return e },
		},
	}

	for _, tc := range hookCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			if err := tc.fn(); err == nil {
				t.Fatalf("expected error in %s", tc.name)
			}
		})
	}
}
