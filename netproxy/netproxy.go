package netproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// ErrListenerClosed is returned when operations are performed on a closed Listener.
var ErrListenerClosed = errors.New("netproxy: listener closed")

// ListenConfig defines a faux-listener for parity with the net package
type ListenConfig struct{}

// Listen returns a Listener that can accept externally offered connections.
func (lc *ListenConfig) Listen(ctx context.Context) (*Listener, error) {
	ctx, cancel := context.WithCancel(ctx)
	ln := &Listener{
		conns:     make(chan net.Conn),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	return ln, nil
}

// Listener implements net.Listener, accepting connections fed in via Offer.
type Listener struct {
	conns     chan net.Conn
	ctx       context.Context
	ctxCancel func()
	closed    atomic.Bool
}

// Offer receives a connection and blocks until it is Accept()ed
func (ln *Listener) Offer(conn net.Conn) error {
	if ln.closed.Load() {
		return ErrListenerClosed
	}

	select {
	case <-ln.ctx.Done():
		return ErrListenerClosed
	case ln.conns <- conn:
		return nil
	}
}

// Accept will block and wait for a new net.Conn
func (ln *Listener) Accept() (net.Conn, error) {
	select {
	case <-ln.ctx.Done():
		return nil, ErrListenerClosed
	case conn, ok := <-ln.conns:
		if !ok {
			return nil, io.EOF
		}
		return conn, nil
	}
}

// Close will close the conns channel
func (ln *Listener) Close() error {
	prevClosed := ln.closed.Swap(true)
	if !prevClosed {
		close(ln.conns)
	}
	return nil
}

// Addr returns a dummy address to satisfy the net.Listener interface.
func (ln *Listener) Addr() net.Addr {
	return dummyLocalAddr{}
}

// dummyLocalAddr is a minimal net.Addr implementation.
type dummyLocalAddr struct{}

func (d dummyLocalAddr) Network() string { return "TODO" }
func (d dummyLocalAddr) String() string  { return "TODO" }
