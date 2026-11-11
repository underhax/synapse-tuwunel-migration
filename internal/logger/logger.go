// Package logger configures structured logging for CLI operations and underlying Matrix cryptographic tracing.
package logger

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rs/zerolog"
)

// Logger aliases zerolog.Logger so callers share one logger type without coupling directly to zerolog configuration.
type Logger = zerolog.Logger

// Nop returns a disabled logger for headless tests and silenced contexts.
func Nop() Logger {
	return zerolog.Nop()
}

// LevelFlag enables a single CLI flag to work as both boolean (--debug) and integer (--debug=2).
type LevelFlag struct {
	Level *int
}

// Set parses either a boolean flag toggle or an explicit integer verbosity level.
func (f *LevelFlag) Set(s string) error {
	if s == "true" {
		*f.Level = 1
		return nil
	}
	if s == "false" {
		*f.Level = 0
		return nil
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("parse debug level: %w", err)
	}
	*f.Level = val
	return nil
}

// String formats the configured verbosity level for flag usage output.
func (f *LevelFlag) String() string {
	if f.Level == nil {
		return "0"
	}
	return strconv.Itoa(*f.Level)
}

// IsBoolFlag tells the standard flag package that the flag may be passed without an explicit value.
func (f *LevelFlag) IsBoolFlag() bool {
	return true
}

// Setup builds a logger tuned for interactive operator output or machine-readable JSON diagnostics.
func Setup(level int, jsonMode bool, out io.Writer) Logger {
	writer := out
	if !jsonMode {
		writer = zerolog.ConsoleWriter{
			Out:        out,
			TimeFormat: time.RFC3339,
		}
	}

	log := zerolog.New(writer).With().Timestamp().Logger()

	switch {
	case level >= 2:
		return log.Level(zerolog.TraceLevel)
	case level == 1:
		return log.Level(zerolog.DebugLevel)
	default:
		return log.Level(zerolog.InfoLevel)
	}
}
