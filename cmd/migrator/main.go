// Package main runs the Synapse-to-Tuwunel Matrix migration CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	_ "maunium.net/go/mautrix/crypto/goolm"

	"github.com/underhax/synapse-tuwunel-migration/internal/cleanup"
	"github.com/underhax/synapse-tuwunel-migration/internal/config"
	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
	"github.com/underhax/synapse-tuwunel-migration/internal/exporter"
	"github.com/underhax/synapse-tuwunel-migration/internal/federation"
	"github.com/underhax/synapse-tuwunel-migration/internal/importer"
	"github.com/underhax/synapse-tuwunel-migration/internal/logger"
	"github.com/underhax/synapse-tuwunel-migration/internal/signingkey"
	"github.com/underhax/synapse-tuwunel-migration/internal/validator"
)

// AppVersion specifies the migration binary version injected at build time.
var AppVersion = "dev"

var (
	osExit               = os.Exit
	signalNotifyContext  = signal.NotifyContext
	getWorkingDir        = os.Getwd
	runPrepareSigningKey = signingkey.Run
	runExport            = exporter.Run
	runImportLocal       = importer.Run
	runFederateSync      = federation.Run
	runCleanup           = cleanup.Run
)

var (
	errUnexpectedArgs = errors.New("unexpected positional arguments")
	errMissingConfig  = errors.New("--config file path is required")
)

type cliOptions struct {
	configPath       string
	modeRaw          string
	debugLevel       int
	jsonMode         bool
	replayNotes      bool
	replayOverridden bool
	showVersion      bool
	showHelp         bool
}

func main() {
	applyStrictUmask()
	if code := execute(os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		osExit(code)
	}
}

func execute(args []string, stdout, stderr io.Writer) int {
	if err := run(args, stdout, stderr); err != nil {
		log := logger.Setup(0, slices.ContainsFunc(args, isJSONArg), stderr)
		log.Error().Err(err).Msg("Migration command failed")
		return 1
	}
	return 0
}

func isJSONArg(arg string) bool {
	return arg == "--json" || arg == "-json" || arg == "--json=true" || arg == "-json=true"
}

func parseArgs(args []string, stderr io.Writer) (*cliOptions, error) {
	fs := flag.NewFlagSet("migrator", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts cliOptions
	fs.StringVar(&opts.configPath, "config", "", "Path to migration JSON configuration manifest inside the 0700 working directory (mode 0400 or 0600)")
	fs.StringVar(&opts.modeRaw, "mode", "", "Migration phase: prepare-signing-key, export, import-local, federate-sync, cleanup")
	fs.Var(&logger.LevelFlag{Level: &opts.debugLevel}, "debug", "Enable debug logging (--debug or --debug=2 for trace)")
	fs.BoolVar(&opts.jsonMode, "json", false, "Emit machine-readable JSON logs on stderr")
	fs.BoolVar(&opts.replayNotes, "replay-notes", false, "Override replay_single_user_notes setting from config")
	fs.BoolVar(&opts.showVersion, "version", false, "Print version information and exit")

	fs.Usage = func() {
		if _, err := fmt.Fprintf(stderr, "Usage: migrator --mode <prepare-signing-key|export|import-local|federate-sync|cleanup> --config <path> [options]\n\nOptions:\n"); err != nil {
			return
		}
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		opts.showHelp = true
		return &opts, nil
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.showHelp = true
			return &opts, nil
		}
		return nil, fmt.Errorf("parse CLI flags: %w", err)
	}

	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%w: %s", errUnexpectedArgs, strings.Join(fs.Args(), " "))
	}

	fs.Visit(func(f *flag.Flag) {
		if f.Name == "replay-notes" {
			opts.replayOverridden = true
		}
	})

	return &opts, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	if opts.showHelp {
		return nil
	}
	if opts.showVersion {
		if _, writeErr := fmt.Fprintf(stdout, "synapse-tuwunel-migrator %s\n", AppVersion); writeErr != nil {
			return fmt.Errorf("write version: %w", writeErr)
		}
		return nil
	}

	mode, err := config.ParseMode(opts.modeRaw)
	if err != nil {
		return fmt.Errorf("parse --mode: %w", err)
	}
	cfgPath := strings.TrimSpace(opts.configPath)
	if cfgPath == "" {
		return errMissingConfig
	}

	workDir, cfg, err := loadConfinedConfig(mode, cfgPath, opts.replayOverridden, opts.replayNotes)
	if err != nil {
		return err
	}

	store, err := dump.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open dump directory %q: %w", cfg.DataDir, err)
	}

	log := logger.Setup(opts.debugLevel, opts.jsonMode, stderr)
	ctx, stop := signalNotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info().
		Str("mode", string(mode)).
		Str("server_name", cfg.ServerName).
		Str("data_dir", cfg.DataDir).
		Int("accounts", len(cfg.Accounts)).
		Msg("Starting migration step")

	if runErr := dispatchMode(ctx, workDir, mode, cfg, store, &log); runErr != nil {
		return runErr
	}

	log.Info().
		Str("mode", string(mode)).
		Msg("Migration step finished successfully")

	return nil
}

func loadConfinedConfig(mode config.Mode, cfgPath string, replayOverridden, replayNotes bool) (string, *config.Config, error) {
	rawWorkDir, err := getWorkingDir()
	if err != nil {
		return "", nil, fmt.Errorf("resolve current working directory: %w", err)
	}
	workDir, err := validator.ValidateWorkspaceDir(rawWorkDir)
	if err != nil {
		return "", nil, fmt.Errorf("validate migration working directory: %w", err)
	}
	confinedCfgPath, err := validator.ConfinePath(workDir, cfgPath, false)
	if err != nil {
		return "", nil, fmt.Errorf("confine --config path: %w", err)
	}

	cfg, err := config.Load(confinedCfgPath)
	if err != nil {
		return "", nil, fmt.Errorf("load config %q: %w", cfgPath, err)
	}
	if replayOverridden {
		cfg.ReplaySingleUserNotes = replayNotes
	}
	if valErr := cfg.ValidateForMode(mode); valErr != nil {
		return "", nil, fmt.Errorf("validate config for mode %s: %w", mode, valErr)
	}

	confinedDataDir, err := validator.ConfinePath(workDir, cfg.DataDir, false)
	if err != nil {
		return "", nil, fmt.Errorf("confine data_dir %q: %w", cfg.DataDir, err)
	}
	cfg.DataDir = confinedDataDir

	return workDir, cfg, nil
}

func dispatchMode(ctx context.Context, workDir string, mode config.Mode, cfg *config.Config, store *dump.Store, log *logger.Logger) error {
	switch mode {
	case config.ModePrepareSigningKey:
		if err := runPrepareSigningKey(ctx, workDir, cfg, store, log); err != nil {
			return fmt.Errorf("prepare-signing-key mode: %w", err)
		}
	case config.ModeExport:
		if err := runExport(ctx, cfg, store, log); err != nil {
			return fmt.Errorf("export mode: %w", err)
		}
	case config.ModeImportLocal:
		if err := runImportLocal(ctx, cfg, store, log); err != nil {
			return fmt.Errorf("import-local mode: %w", err)
		}
	case config.ModeFederateSync:
		if err := runFederateSync(ctx, cfg, store, log); err != nil {
			return fmt.Errorf("federate-sync mode: %w", err)
		}
	case config.ModeCleanup:
		if err := runCleanup(ctx, cfg, store, log); err != nil {
			return fmt.Errorf("cleanup mode: %w", err)
		}
	default:
		return fmt.Errorf("%w: %q", config.ErrInvalidMode, mode)
	}
	return nil
}
