package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// ErrListenerClosed is returned when operations are performed on a closed Listener.
var ErrListenerClosed = fmt.Errorf("netproxy: listener closed: %w", net.ErrClosed)

type InjectListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	Inject(net.Conn) error
}

// Listen returns a faux Listener that can accept externally offered connections.
func Listen(ctx context.Context) (*Listener, error) {
	ctx, cancel := context.WithCancel(ctx)
	ln := &Listener{
		conns:     make(chan net.Conn),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	return ln, nil
}

func NewListener(ctx context.Context) InjectListener {
	ln, _ := Listen(ctx)
	return ln
}

// Listener implements net.Listener, accepting connections fed in via Offer.
type Listener struct {
	conns     chan net.Conn
	ctx       context.Context
	ctxCancel func()
	closed    atomic.Bool
}

// Inject receives a connection and blocks until it is Accept()ed
func (ln *Listener) Inject(conn net.Conn) error {
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

var (
	_ InjectListener = (*Listener)(nil)
)
