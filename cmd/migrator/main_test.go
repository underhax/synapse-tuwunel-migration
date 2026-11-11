package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/logger"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

func newTestWorkspace(t *testing.T, name string) string {
	t.Helper()
	ws := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatalf("mkdir workspace %s: %v", ws, err)
	}
	canon, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatalf("eval workspace symlinks %s: %v", ws, err)
	}
	return canon
}

type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("injected write error")
}

func writeTestConfigFile(t *testing.T, dir, filename string, perm os.FileMode, mutate func(*config.Config)) (string, *config.Config) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	cfg := &config.Config{
		ServerName:            "alpha.example.com",
		SynapseURL:            "https://synapse.alpha.example.com",
		TuwunelURL:            "https://tuwunel.alpha.example.com",
		TuwunelSharedSecret:   "test-shared-secret",
		DataDir:               filepath.Join(dir, "dump"),
		LocalRoomVersion:      "12",
		ReplaySingleUserNotes: true,
		Accounts: []config.AccountConfig{
			{
				UserID:          "@alice:alpha.example.com",
				SynapsePassword: "example-syn-password",
				TuwunelPassword: "example-tuw-password",
				RecoveryKey:     "EsTexampleRecoveryKeyForTestingOnly",
				Admin:           true,
			},
		},
	}
	if mutate != nil {
		mutate(cfg)
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	cfgPath := filepath.Join(dir, filename)
	if writeErr := os.WriteFile(cfgPath, raw, 0o600); writeErr != nil {
		t.Fatalf("write config %s: %v", cfgPath, writeErr)
	}
	if chmodErr := os.Chmod(cfgPath, perm); chmodErr != nil {
		t.Fatalf("chmod config %s: %v", cfgPath, chmodErr)
	}
	return cfgPath, cfg
}

func buildCLIArgs(mode, cfgPath, replayFlag, debugFlag string, jsonMode bool, extra ...string) []string {
	var args []string
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	if cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}
	if replayFlag != "" {
		args = append(args, replayFlag)
	}
	if debugFlag != "" {
		args = append(args, debugFlag)
	}
	if jsonMode {
		args = append(args, "--json")
	}
	return append(args, extra...)
}

func TestMainEntry(t *testing.T) {
	origExit := osExit
	origArgs := os.Args
	t.Cleanup(func() {
		osExit = origExit
		os.Args = origArgs
	})

	exitCode := -1
	osExit = func(code int) {
		exitCode = code
	}

	os.Args = []string{"migrator", "-version"}
	main()
	if exitCode != -1 {
		t.Fatalf("expected osExit not called on -version, got code %d", exitCode)
	}

	os.Args = []string{"migrator", "--unknown-main-flag"}
	main()
	if exitCode != 1 {
		t.Fatalf("expected osExit(1) on invalid CLI args, got %d", exitCode)
	}
}

func TestHelpAndVersion(t *testing.T) {
	origVersion := AppVersion
	AppVersion = "v9.9.9-test"
	t.Cleanup(func() { AppVersion = origVersion })

	tests := []struct {
		name       string
		wantStdout string
		wantStderr string
		args       []string
		wantCode   int
		failStdout bool
		failStderr bool
	}{
		{
			name:       "no args prints usage",
			args:       nil,
			wantCode:   0,
			wantStderr: "Usage: migrator",
		},
		{
			name:       "help flag prints options",
			args:       []string{"--help"},
			wantCode:   0,
			wantStderr: "Options:",
		},
		{
			name:       "usage write error tolerated",
			args:       nil,
			failStderr: true,
			wantCode:   0,
		},
		{
			name:       "version flag prints AppVersion",
			args:       []string{"--version"},
			wantCode:   0,
			wantStdout: "synapse-tuwunel-migrator v9.9.9-test",
		},
		{
			name:       "version write error returns code 1",
			args:       []string{"--version"},
			failStdout: true,
			wantCode:   1,
			wantStderr: "write version",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			stdoutWriter := &outBuf
			stderrWriter := &errBuf
			var code int

			switch {
			case tc.failStdout:
				code = execute(tc.args, failingWriter{}, stderrWriter)
			case tc.failStderr:
				code = execute(tc.args, stdoutWriter, failingWriter{})
			default:
				code = execute(tc.args, stdoutWriter, stderrWriter)
			}

			if code != tc.wantCode {
				t.Fatalf("execute code = %d, want %d (stderr=%s)", code, tc.wantCode, errBuf.String())
			}
			if tc.wantStdout != "" && !strings.Contains(outBuf.String(), tc.wantStdout) {
				t.Fatalf("stdout = %q, want substring %q", outBuf.String(), tc.wantStdout)
			}
			if tc.wantStderr != "" && !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", errBuf.String(), tc.wantStderr)
			}
		})
	}
}

func TestExecuteFlagConfigAndStoreErrors(t *testing.T) {
	dir := newTestWorkspace(t, "errors-ws")
	t.Chdir(dir)

	validCfgPath, _ := writeTestConfigFile(t, filepath.Join(dir, "valid"), "migration.json", 0o600, nil)
	insecureCfgPath, _ := writeTestConfigFile(t, filepath.Join(dir, "insecure_cfg"), "migration.json", 0o644, nil)
	missingAuthCfgPath, _ := writeTestConfigFile(t, filepath.Join(dir, "missing_auth"), "migration.json", 0o600, func(c *config.Config) {
		c.Accounts[0].SynapsePassword = ""
		c.Accounts[0].SynapseAccessToken = ""
	})

	badDumpRoot := filepath.Join(dir, "bad_dump_dir")
	if err := os.MkdirAll(badDumpRoot, 0o700); err != nil {
		t.Fatalf("mkdir badDumpRoot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(badDumpRoot, "dump"), []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("write dump file blocker: %v", err)
	}
	badDumpCfgPath, _ := writeTestConfigFile(t, badDumpRoot, "migration.json", 0o600, nil)

	tests := []struct {
		name       string
		wantStderr string
		args       []string
		wantJSON   bool
	}{
		{
			name:       "unknown CLI flag",
			args:       []string{"--unknown-cli-flag"},
			wantStderr: "parse CLI flags",
		},
		{
			name:       "unexpected positional argument",
			args:       buildCLIArgs(string(config.ModeExport), validCfgPath, "", "", false, "positional-arg"),
			wantStderr: "unexpected positional arguments",
		},
		{
			name:       "unsupported mode with json flag",
			args:       buildCLIArgs("invalid-mode", validCfgPath, "", "", true),
			wantStderr: "parse --mode",
			wantJSON:   true,
		},
		{
			name:       "missing config path",
			args:       buildCLIArgs(string(config.ModeExport), "", "", "", false),
			wantStderr: "--config file path is required",
		},
		{
			name:       "nonexistent config file",
			args:       buildCLIArgs(string(config.ModeExport), filepath.Join(dir, "missing.json"), "", "", false),
			wantStderr: "load config",
		},
		{
			name:       "insecure config permissions rejected",
			args:       buildCLIArgs(string(config.ModeExport), insecureCfgPath, "", "", false),
			wantStderr: "insecure file or directory permissions",
		},
		{
			name:       "validate config fails when mode credentials missing",
			args:       buildCLIArgs(string(config.ModeExport), missingAuthCfgPath, "", "", false),
			wantStderr: "validate config for mode export",
		},
		{
			name:       "open non-directory dump path rejected",
			args:       buildCLIArgs(string(config.ModeExport), badDumpCfgPath, "", "", false),
			wantStderr: "open dump directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			code := execute(tc.args, &outBuf, &errBuf)
			if code != 1 {
				t.Fatalf("execute code = %d, want 1 (stderr=%s)", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", errBuf.String(), tc.wantStderr)
			}
			if tc.wantJSON {
				var parsed map[string]any
				if err := json.Unmarshal(bytes.TrimSpace(errBuf.Bytes()), &parsed); err != nil {
					t.Fatalf("expected valid JSON error output, got %q: %v", errBuf.String(), err)
				}
				if parsed["level"] != "error" {
					t.Fatalf("expected level=error in JSON, got %v", parsed["level"])
				}
			}
		})
	}
}

func TestExecuteWorkspaceAndConfinementErrors(t *testing.T) {
	t.Run("injected getWorkingDir failure", func(t *testing.T) {
		ws := newTestWorkspace(t, "wd-err-ws")
		t.Chdir(ws)
		cfgPath, _ := writeTestConfigFile(t, filepath.Join(ws, "cfg"), "wd-err.json", 0o600, nil)

		origGetWD := getWorkingDir
		t.Cleanup(func() { getWorkingDir = origGetWD })
		getWorkingDir = failingGetWorkingDir

		var outBuf, errBuf bytes.Buffer
		code := execute(buildCLIArgs(string(config.ModeExport), cfgPath, "", "", false), &outBuf, &errBuf)
		if code != 1 || !strings.Contains(errBuf.String(), "injected getwd failure") {
			t.Fatalf("expected getwd error, code=%d stderr=%s", code, errBuf.String())
		}
	})

	t.Run("non-0700 working directory rejected", func(t *testing.T) {
		badWS := filepath.Join(t.TempDir(), "open-ws")
		if err := os.MkdirAll(badWS, 0o700); err != nil {
			t.Fatalf("mkdir open-ws: %v", err)
		}
		if err := os.Chmod(badWS, 0o400); err != nil {
			t.Fatalf("chmod open-ws: %v", err)
		}
		origGetWD := getWorkingDir
		t.Cleanup(func() { getWorkingDir = origGetWD })
		getWorkingDir = func() (string, error) { return badWS, nil }

		var outBuf, errBuf bytes.Buffer
		code := execute(buildCLIArgs(string(config.ModeExport), "open-ws.json", "", "", false), &outBuf, &errBuf)
		if code != 1 || !strings.Contains(errBuf.String(), validator.ErrInsecurePermission.Error()) {
			t.Fatalf("expected insecure workspace error, code=%d stderr=%s", code, errBuf.String())
		}
	})
}

func TestExecutePathConfinementErrors(t *testing.T) {
	parentDir := t.TempDir()
	outsideDir := filepath.Join(parentDir, "outside")
	outsideCfg, _ := writeTestConfigFile(t, outsideDir, "outside.json", 0o600, nil)

	ws := filepath.Join(parentDir, "confined-ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatalf("mkdir confined-ws: %v", err)
	}
	t.Chdir(ws)

	symlinkCfg := filepath.Join(ws, "link.json")
	if err := os.Symlink(outsideCfg, symlinkCfg); err != nil {
		t.Fatalf("symlink config: %v", err)
	}

	outsideDumpSymlink := filepath.Join(ws, "dump-link")
	if err := os.Symlink(outsideDir, outsideDumpSymlink); err != nil {
		t.Fatalf("symlink dump: %v", err)
	}

	parentEscapeCfg, _ := writeTestConfigFile(t, ws, "escape-data.json", 0o600, func(c *config.Config) {
		c.DataDir = "../outside-dump"
	})
	rootDotCfg, _ := writeTestConfigFile(t, ws, "root-data.json", 0o600, func(c *config.Config) {
		c.DataDir = "."
	})
	symlinkDataCfg, _ := writeTestConfigFile(t, ws, "symlink-data.json", 0o600, func(c *config.Config) {
		c.DataDir = "dump-link"
	})

	cases := []struct {
		name          string
		cfgPath       string
		wantTargetSub string
		isDataDir     bool
	}{
		{
			name:          "config traversal outside workspace",
			cfgPath:       "../outside/outside.json",
			wantTargetSub: "outside.json",
		},
		{
			name:          "config symlink outside workspace",
			cfgPath:       "link.json",
			wantTargetSub: "link.json",
		},
		{
			name:          "data_dir traversal outside workspace",
			cfgPath:       parentEscapeCfg,
			wantTargetSub: "outside-dump",
			isDataDir:     true,
		},
		{
			name:          "data_dir workspace root dot rejected",
			cfgPath:       rootDotCfg,
			wantTargetSub: `\".\"`,
			isDataDir:     true,
		},
		{
			name:          "data_dir symlink outside workspace",
			cfgPath:       symlinkDataCfg,
			wantTargetSub: "dump-link",
			isDataDir:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			code := execute(buildCLIArgs(string(config.ModePrepareSigningKey), tc.cfgPath, "", "", false), &outBuf, &errBuf)
			if code != 1 {
				t.Fatalf("expected failure exit code 1, got %d (stderr=%s)", code, errBuf.String())
			}
			wantOp := "confine --config path"
			if tc.isDataDir {
				wantOp = "confine data_dir"
			}
			gotStderr := errBuf.String()
			if !strings.Contains(gotStderr, wantOp) || !strings.Contains(gotStderr, tc.wantTargetSub) || !strings.Contains(gotStderr, validator.ErrPathOutsideWorkspace.Error()) {
				t.Fatalf("stderr = %q, want %q, %q, and %q", gotStderr, wantOp, tc.wantTargetSub, validator.ErrPathOutsideWorkspace.Error())
			}
		})
	}
}

func TestExecuteAllModes(t *testing.T) {
	origPrep := runPrepareSigningKey
	origExport := runExport
	origImport := runImportLocal
	origFed := runFederateSync
	origCleanup := runCleanup
	t.Cleanup(func() {
		runPrepareSigningKey = origPrep
		runExport = origExport
		runImportLocal = origImport
		runFederateSync = origFed
		runCleanup = origCleanup
	})

	var (
		gotMode    config.Mode
		gotWorkDir string
		gotReplay  bool
		gotStore   string
		gotLevel   zerolog.Level
	)

	makeRecorder := func(mode config.Mode) func(context.Context, *config.Config, *dump.Store, *zerolog.Logger) error {
		return func(_ context.Context, cfg *config.Config, store *dump.Store, log *zerolog.Logger) error {
			gotMode = mode
			gotWorkDir = ""
			gotReplay = cfg.ReplaySingleUserNotes
			gotStore = store.Root()
			gotLevel = log.GetLevel()
			return nil
		}
	}

	runPrepareSigningKey = func(_ context.Context, workDir string, cfg *config.Config, store *dump.Store, log *zerolog.Logger) error {
		gotMode = config.ModePrepareSigningKey
		gotWorkDir = workDir
		gotReplay = cfg.ReplaySingleUserNotes
		gotStore = store.Root()
		gotLevel = log.GetLevel()
		return nil
	}
	runExport = makeRecorder(config.ModeExport)
	runImportLocal = makeRecorder(config.ModeImportLocal)
	runFederateSync = makeRecorder(config.ModeFederateSync)
	runCleanup = makeRecorder(config.ModeCleanup)

	dir := newTestWorkspace(t, "modes-ws")
	t.Chdir(dir)

	_, prepCfg := writeTestConfigFile(t, filepath.Join(dir, "prep"), "prepare.json", 0o400, func(c *config.Config) {
		c.ReplaySingleUserNotes = false
		c.DataDir = "./prep/dump"
		c.Accounts[0].SynapsePassword = ""
		c.Accounts[0].TuwunelPassword = ""
		c.Accounts[0].RecoveryKey = ""
	})
	_ = prepCfg
	cfgPath, stdCfg := writeTestConfigFile(t, filepath.Join(dir, "std"), "migration.json", 0o600, nil)
	cleanupCfgPath, cleanCfg := writeTestConfigFile(t, filepath.Join(dir, "clean"), "cleanup.json", 0o400, func(c *config.Config) {
		c.ReplaySingleUserNotes = false
		c.Accounts[0].SynapsePassword = ""
		c.Accounts[0].TuwunelPassword = ""
		c.Accounts[0].RecoveryKey = ""
	})

	successCases := []struct {
		name        string
		mode        config.Mode
		cfgPath     string
		wantWorkDir string
		wantDir     string
		replayFlag  string
		debugFlag   string
		jsonMode    bool
		wantReplay  bool
		wantLevel   zerolog.Level
		wantJSONOut bool
	}{
		{
			name:        "prepare-signing-key resolves relative config and data_dir inside workspace",
			mode:        config.ModePrepareSigningKey,
			cfgPath:     "prep/prepare.json",
			wantWorkDir: dir,
			wantDir:     filepath.Join(dir, "prep", "dump"),
			wantReplay:  false,
			wantLevel:   zerolog.InfoLevel,
		},
		{
			name:       "export preserves JSON replay setting and info level",
			mode:       config.ModeExport,
			cfgPath:    cfgPath,
			wantDir:    stdCfg.DataDir,
			wantReplay: true,
			wantLevel:  zerolog.InfoLevel,
		},
		{
			name:       "import-local overrides replay false and sets debug level",
			mode:       config.ModeImportLocal,
			cfgPath:    cfgPath,
			wantDir:    stdCfg.DataDir,
			replayFlag: "--replay-notes=false",
			debugFlag:  "--debug",
			wantReplay: false,
			wantLevel:  zerolog.DebugLevel,
		},
		{
			name:        "federate-sync uses trace level 2 and json stderr",
			mode:        config.ModeFederateSync,
			cfgPath:     cfgPath,
			wantDir:     stdCfg.DataDir,
			debugFlag:   "--debug=2",
			jsonMode:    true,
			wantReplay:  true,
			wantLevel:   zerolog.TraceLevel,
			wantJSONOut: true,
		},
		{
			name:       "cleanup works with 0400 config without secrets and replay true override",
			mode:       config.ModeCleanup,
			cfgPath:    cleanupCfgPath,
			wantDir:    cleanCfg.DataDir,
			replayFlag: "--replay-notes",
			wantReplay: true,
			wantLevel:  zerolog.InfoLevel,
		},
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			args := buildCLIArgs(string(tc.mode), tc.cfgPath, tc.replayFlag, tc.debugFlag, tc.jsonMode)
			code := execute(args, &outBuf, &errBuf)
			if code != 0 {
				t.Fatalf("execute code = %d, want 0 (stderr=%s)", code, errBuf.String())
			}
			if gotMode != tc.mode {
				t.Fatalf("runner got mode %q, want %q", gotMode, tc.mode)
			}
			if gotWorkDir != tc.wantWorkDir {
				t.Fatalf("runner got workDir %q, want %q", gotWorkDir, tc.wantWorkDir)
			}
			if gotReplay != tc.wantReplay {
				t.Fatalf("runner got ReplaySingleUserNotes=%v, want %v", gotReplay, tc.wantReplay)
			}
			if gotStore != tc.wantDir {
				t.Fatalf("runner got store root %q, want %q", gotStore, tc.wantDir)
			}
			if gotLevel != tc.wantLevel {
				t.Fatalf("runner got log level %v, want %v", gotLevel, tc.wantLevel)
			}
			if tc.wantJSONOut && !strings.Contains(errBuf.String(), `"message":"Migration step finished successfully"`) {
				t.Fatalf("expected structured JSON completion log, got %s", errBuf.String())
			}
		})
	}
}

func TestExecuteRunnerErrorsAndInvalidDispatch(t *testing.T) {
	origPrep := runPrepareSigningKey
	origExport := runExport
	origImport := runImportLocal
	origFed := runFederateSync
	origCleanup := runCleanup
	t.Cleanup(func() {
		runPrepareSigningKey = origPrep
		runExport = origExport
		runImportLocal = origImport
		runFederateSync = origFed
		runCleanup = origCleanup
	})

	runPrepareSigningKey = failingPrepareRunner
	failRunner := func(context.Context, *config.Config, *dump.Store, *zerolog.Logger) error {
		return errors.New("runner failed")
	}
	runExport = failRunner
	runImportLocal = failRunner
	runFederateSync = failRunner
	runCleanup = failRunner

	dir := newTestWorkspace(t, "runner-err-ws")
	t.Chdir(dir)
	cfgPath, cfg := writeTestConfigFile(t, filepath.Join(dir, "err"), "migration.json", 0o600, nil)

	failureCases := []struct {
		mode       config.Mode
		wantStderr string
	}{
		{mode: config.ModePrepareSigningKey, wantStderr: "prepare-signing-key mode: runner failed"},
		{mode: config.ModeExport, wantStderr: "export mode: runner failed"},
		{mode: config.ModeImportLocal, wantStderr: "import-local mode: runner failed"},
		{mode: config.ModeFederateSync, wantStderr: "federate-sync mode: runner failed"},
		{mode: config.ModeCleanup, wantStderr: "cleanup mode: runner failed"},
	}

	for _, tc := range failureCases {
		t.Run("runner error_"+string(tc.mode), func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			code := execute(buildCLIArgs(string(tc.mode), cfgPath, "", "", false), &outBuf, &errBuf)
			if code != 1 {
				t.Fatalf("execute code = %d, want 1", code)
			}
			if !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", errBuf.String(), tc.wantStderr)
			}
		})
	}

	t.Run("dispatchMode invalid mode", func(t *testing.T) {
		store, err := dump.Open(cfg.DataDir)
		if err != nil {
			t.Fatalf("dump.Open: %v", err)
		}
		log := logger.Nop()
		if err := dispatchMode(context.Background(), dir, config.Mode("bogus"), cfg, store, &log); !errors.Is(err, config.ErrInvalidMode) {
			t.Fatalf("expected config.ErrInvalidMode, got %v", err)
		}
	})
}

func failingGetWorkingDir() (string, error) {
	return "", errors.New("injected getwd failure")
}

func failingPrepareRunner(_ context.Context, _ string, _ *config.Config, _ *dump.Store, _ *zerolog.Logger) error {
	return errors.New("runner failed")
}
