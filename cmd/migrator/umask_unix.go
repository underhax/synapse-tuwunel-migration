//go:build unix

package main

import "syscall"

func applyStrictUmask() {
	syscall.Umask(0o077)
}
