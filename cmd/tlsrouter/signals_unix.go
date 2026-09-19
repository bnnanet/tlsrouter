//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"os"
	"os/signal"
	"syscall"
)

var (
	sigReload = syscall.SIGUSR1
	sigTerm   = syscall.SIGTERM
	sigInt    = syscall.SIGINT
)

func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, sigReload, sigTerm, sigInt)
}
