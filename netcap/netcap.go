package netcap

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// ErrListenerClosed is returned when operations are performed on a closed Listener.
var ErrListenerClosed = errors.New("netproxy: listener closed")

type TunnelListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	Inject(net.Conn) error
}

// Listen returns a TunnelListener that can accept injected / side-loaded connections
func Listen(ctx context.Context) (TunnelListener, error) {
	ctx, cancel := context.WithCancel(ctx)
	ln := &dummyListener{
		conns:     make(chan net.Conn),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	return ln, nil
}

func NewListener(ctx context.Context) TunnelListener {
	ln, _ := Listen(ctx)
	return ln
}

// dummyListener implements net.Listener, accepting connections fed in via Inject.
type dummyListener struct {
	conns     chan net.Conn
	ctx       context.Context
	ctxCancel func()
	closed    atomic.Bool
}

// Inject receives a connection and blocks until it is Accept()ed
func (ln *dummyListener) Inject(conn net.Conn) error {
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
func (ln *dummyListener) Accept() (net.Conn, error) {
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
func (ln *dummyListener) Close() error {
	prevClosed := ln.closed.Swap(true)
	if !prevClosed {
		close(ln.conns)
	}
	return nil
}

// Addr returns a dummy address to satisfy the net.Listener interface.
func (ln *dummyListener) Addr() net.Addr {
	return dummyLocalAddr{}
}

// dummyLocalAddr is a minimal net.Addr implementation.
type dummyLocalAddr struct{}

func (d dummyLocalAddr) Network() string { return "TODO" }
func (d dummyLocalAddr) String() string  { return "TODO" }
