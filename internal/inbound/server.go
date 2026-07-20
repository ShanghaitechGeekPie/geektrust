// Package inbound exposes the tunnel as local SOCKS5 and HTTP CONNECT
// proxies. It depends only on the Dialer and Resolver contracts, never on
// aTrust internals.
package inbound

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/resolver"
)

// maxConcurrent caps per-listener connections so a runaway client cannot
// exhaust goroutines or tunnel conntrack slots.
const maxConcurrent = 256

// Dialer establishes a TCP connection through the tunnel to an
// already-resolved IP under the given authorizing app. Implemented by
// l3.Dialer.
type Dialer interface {
	Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
}

// Resolver maps a target host to a tunnel target (IP, authorizing appId,
// and the domain for wildcard-authorized dials). Implemented by
// resolver.Resolver.
type Resolver interface {
	Resolve(ctx context.Context, host string, port int) (resolver.Resolution, error)
}

// Server runs the SOCKS5 and HTTP CONNECT listeners.
type Server struct {
	cfg      config.Inbound
	resolver Resolver
	dialer   Dialer
	logger   *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// New builds the proxy server.
func New(cfg config.Inbound, resolver Resolver, dialer Dialer, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, resolver: resolver, dialer: dialer, logger: logger,
		conns: make(map[net.Conn]struct{})}
}

// handshakeLimit bounds the protocol handshake phase so a silent peer cannot
// hold a concurrency slot forever; handlers clear it before relaying.
const handshakeLimit = 30 * time.Second

// Run listens and serves until ctx is cancelled, then shuts down in order:
// stop acceptors, close tracked connections, join handlers.
func (s *Server) Run(ctx context.Context) error {
	type listener struct {
		ln     net.Listener
		handle func(context.Context, net.Conn)
		proto  string
	}
	// Open every listener before starting any accept loop: a late bind
	// failure must not leave a sibling loop spinning on a closed listener.
	var listeners []listener
	if s.cfg.SOCKS5.Enabled {
		ln, err := net.Listen("tcp", s.cfg.SOCKS5.Listen)
		if err != nil {
			return err
		}
		listeners = append(listeners, listener{ln, s.handleSOCKS5, "socks5"})
	}
	if s.cfg.HTTP.Enabled {
		ln, err := net.Listen("tcp", s.cfg.HTTP.Listen)
		if err != nil {
			for _, l := range listeners {
				l.ln.Close()
			}
			return err
		}
		listeners = append(listeners, listener{ln, s.handleHTTPConnect, "http"})
	}
	if len(listeners) == 0 {
		return errors.New("no proxy listeners enabled (inbound.socks5 / inbound.http)")
	}

	var acceptWG, handlerWG sync.WaitGroup
	for _, l := range listeners {
		s.logger.Info("proxy listening", "proto", l.proto, "addr", l.ln.Addr().String())
		acceptWG.Add(1)
		go func(l listener) {
			defer acceptWG.Done()
			s.acceptLoop(ctx, l.ln, l.handle, l.proto, &handlerWG)
		}(l)
	}

	<-ctx.Done()
	// 1. Stop acceptors and join them, so nothing new is tracked past the
	//    snapshot below.
	for _, l := range listeners {
		l.ln.Close()
	}
	acceptWG.Wait()
	// 2. Force active relays to unwind.
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	// 3. Wait for handlers to finish tearing down.
	handlerWG.Wait()
	return nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, handle func(context.Context, net.Conn), proto string, handlerWG *sync.WaitGroup) {
	sem := make(chan struct{}, maxConcurrent)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.logger.Warn("accept failed", "proto", proto, "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.logger.Warn("connection limit reached, rejecting", "proto", proto)
			conn.Close()
			continue
		}
		s.track(conn, true)
		handlerWG.Add(1)
		go func() {
			defer func() { <-sem; s.track(conn, false); conn.Close(); handlerWG.Done() }()
			// Bound the handshake; the handler clears the deadline once the
			// tunnel relay starts.
			conn.SetDeadline(time.Now().Add(handshakeLimit))
			handle(ctx, conn)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.mu.Unlock()
}

// relayPair copies both directions until the first side ends, then tears
// the pair down.
func relayPair(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
