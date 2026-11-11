//go:build unix

package main

import (
	"syscall"
	"testing"
)

func TestApplyStrictUmask(t *testing.T) {
	oldUmask := syscall.Umask(0)
	syscall.Umask(oldUmask)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	applyStrictUmask()

	currentUmask := syscall.Umask(oldUmask)
	if currentUmask != 0o077 {
		t.Fatalf("expected umask 0077, got %04o", currentUmask)
	}
}
