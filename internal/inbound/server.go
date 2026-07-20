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

const (
	// maxConcurrent caps per-listener connections so a runaway client cannot
	// exhaust goroutines or tunnel conntrack slots.
	maxConcurrent = 256
	// A clean EOF half-closes the opposite write side. Bound the time allowed
	// for the peer's remaining response/FIN so abandoned clients cannot leak.
	halfCloseTimeout = 30 * time.Second
)

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

var relayBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, 32*1024)
	return &buffer
}}

type closeWriter interface {
	CloseWrite() error
}

type activityReader struct {
	io.Reader
	activity chan<- struct{}
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		select {
		case r.activity <- struct{}{}:
		default:
		}
	}
	return n, err
}

// relayPair preserves TCP half-closes: EOF in one direction sends FIN but
// leaves the reverse stream alive. Protocols that send a request through EOF
// and then read a response therefore work through both inbound proxy types.
func relayPair(a, b net.Conn) {
	relayPairWithIdleTimeout(a, b, halfCloseTimeout)
}

func relayPairWithIdleTimeout(a, b net.Conn, idleTimeout time.Duration) {
	done := make(chan error, 2)
	activity := make(chan struct{}, 1)
	copyStream := func(dst, src net.Conn) {
		buffer := relayBuffers.Get().(*[]byte)
		_, err := io.CopyBuffer(dst, activityReader{Reader: src, activity: activity}, *buffer)
		relayBuffers.Put(buffer)
		if err == nil {
			if writer, ok := dst.(closeWriter); ok {
				err = writer.CloseWrite()
			} else {
				err = dst.Close()
			}
		}
		done <- err
	}
	go copyStream(a, b)
	go copyStream(b, a)

	firstErr := <-done
	if firstErr != nil {
		a.Close()
		b.Close()
		<-done
		return
	}
	// Discard activity from before the first FIN. From this point onward the
	// timeout measures idleness in the still-open reverse direction.
drain:
	for {
		select {
		case <-activity:
		default:
			break drain
		}
	}

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-done:
			a.Close()
			b.Close()
			return
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			a.Close()
			b.Close()
			<-done
			return
		}
	}
}
