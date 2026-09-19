//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package tlsrouter

import "syscall"

// reusePort is a no-op on platforms that do not support SO_REUSEPORT.
// See: https://github.com/bnnanet/tlsrouter/issues — add per-platform
// socket option support for illumos, solaris, plan9, wasip1, js/wasm.
func reusePort(network, address string, conn syscall.RawConn) error {
	return nil
}

// Reincarnate is a no-op on platforms without Unix signals.
func (c *Config) Reincarnate() {}
