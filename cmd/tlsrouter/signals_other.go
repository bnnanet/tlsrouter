//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package main

import "os"

// Unix signals are not available on these platforms.
// SIGUSR1 reload and SIGINT/SIGTERM graceful shutdown are no-ops here.
// See: https://github.com/bnnanet/tlsrouter/issues — add per-platform
// signal support for windows, plan9, js/wasm, etc.

var (
	sigReload os.Signal = nil
	sigTerm   os.Signal = nil
	sigInt    os.Signal = nil
)

func notifySignals(_ chan os.Signal) {}
