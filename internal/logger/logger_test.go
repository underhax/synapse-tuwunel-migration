package logger

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestNop(t *testing.T) {
	t.Parallel()

	log := Nop()
	if log.GetLevel() != zerolog.Disabled {
		t.Fatalf("expected disabled level, got %v", log.GetLevel())
	}
}

func TestLevelFlag(t *testing.T) {
	t.Parallel()

	var emptyFlag LevelFlag
	if emptyFlag.String() != "0" {
		t.Fatalf("expected default string 0, got %q", emptyFlag.String())
	}
	if !emptyFlag.IsBoolFlag() {
		t.Fatal("expected IsBoolFlag to return true")
	}

	tests := []struct {
		name    string
		input   string
		wantStr string
		want    int
		wantErr bool
	}{
		{name: "bool true", input: "true", want: 1, wantStr: "1"},
		{name: "bool false", input: "false", want: 0, wantStr: "0"},
		{name: "numeric 2", input: "2", want: 2, wantStr: "2"},
		{name: "numeric 0", input: "0", want: 0, wantStr: "0"},
		{name: "invalid", input: "abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lvl := 0
			flag := LevelFlag{Level: &lvl}
			err := flag.Set(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if lvl != tc.want {
				t.Fatalf("expected level %d, got %d", tc.want, lvl)
			}
			if flag.String() != tc.wantStr {
				t.Fatalf("expected String() %q, got %q", tc.wantStr, flag.String())
			}
		})
	}
}

func TestSetup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		level     int
		jsonMode  bool
		wantLevel zerolog.Level
	}{
		{name: "default console info", level: 0, jsonMode: false, wantLevel: zerolog.InfoLevel},
		{name: "debug console", level: 1, jsonMode: false, wantLevel: zerolog.DebugLevel},
		{name: "trace json", level: 2, jsonMode: true, wantLevel: zerolog.TraceLevel},
		{name: "high trace json", level: 5, jsonMode: true, wantLevel: zerolog.TraceLevel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := Setup(tc.level, tc.jsonMode, &buf)
			if log.GetLevel() != tc.wantLevel {
				t.Fatalf("expected level %v, got %v", tc.wantLevel, log.GetLevel())
			}
			log.Error().Msg("probe")
			if !strings.Contains(buf.String(), "probe") {
				t.Fatalf("expected log output to contain probe, got %q", buf.String())
			}
		})
	}
}
