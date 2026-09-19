//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package tlsrouter

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func reusePort(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		_ = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
}

func (c *Config) Reincarnate() {
	c.sigChan <- syscall.SIGUSR1
}
