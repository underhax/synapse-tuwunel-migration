//go:build !unix

package main

import "testing"

func TestApplyStrictUmask(t *testing.T) {
	applyStrictUmask()
}
