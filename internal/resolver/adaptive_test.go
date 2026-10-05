package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsDrop int32 = iota
	dnsAnswer
	dnsNegative
	dnsServfail
	dnsTruncated
	dnsFake
	dnsLowercase
)

type dnsFixture struct {
	udp                *net.UDPConn
	tcp                net.Listener
	udpMode, tcpMode   atomic.Int32
	udpCalls, tcpCalls atomic.Int32
	udpEntered         chan struct{}
	entered            sync.Once
}

func newDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		u.Close()
		t.Fatal(e)
	}
	f := &dnsFixture{udp: u, tcp: l, udpEntered: make(chan struct{})}
	f.udpMode.Store(dnsAnswer)
	f.tcpMode.Store(dnsAnswer)
	t.Cleanup(func() { u.Close(); l.Close() })
	go func() {
		for {
			b := make([]byte, 4096)
			n, a, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			if reply := fixtureReply(b[:n], f.udpMode.Load()); reply != nil {
				u.WriteToUDP(reply, a)
			}
		}
	}()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				prefix := make([]byte, 2)
				if _, e := io.ReadFull(c, prefix); e != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(prefix)))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				reply := fixtureReply(b, f.tcpMode.Load())
				if reply == nil {
					return
				}
				wire := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
				wire = append(wire, reply...)
				// Exercise stream observation across length-prefix and body boundaries.
				for _, part := range [][]byte{wire[:1], wire[1:2], wire[2:8], wire[8:]} {
					if _, e := c.Write(part); e != nil {
						return
					}
				}
			}()
		}
	}()
	return f
}
func fixtureReply(wire []byte, mode int32) []byte {
	if mode == dnsDrop {
		return nil
	}
	var q dnsmessage.Message
	if q.Unpack(wire) != nil || len(q.Questions) != 1 {
		return nil
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
	switch mode {
	case dnsNegative:
		msg.RCode = dnsmessage.RCodeNameError
	case dnsServfail:
		msg.RCode = dnsmessage.RCodeServerFailure
	case dnsTruncated:
		msg.Truncated = true
	default:
		if mode == dnsLowercase {
			name, _ := dnsmessage.NewName(strings.ToLower(q.Questions[0].Name.String()))
			msg.Questions[0].Name = name
		}
		ip := [4]byte{10, 20, 30, 40}
		if mode == dnsFake {
			ip = [4]byte{198, 18, 0, 1}
		}
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}}}
	}
	b, _ := msg.Pack()
	return b
}
func (f *dnsFixture) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network == "udp" {
		f.udpCalls.Add(1)
		f.entered.Do(func() { close(f.udpEntered) })
		return (&net.Dialer{}).DialContext(ctx, "udp", f.udp.LocalAddr().String())
	}
	f.tcpCalls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", f.tcp.Addr().String())
}
func testDNSPool() *dnsPool {
	p := newDNSPool()
	p.policy.udpTimeout = 50 * time.Millisecond
	p.policy.tcpTimeout = 200 * time.Millisecond
	return p
}
func poolLookup(p *dnsPool, host string, dial dnsDialFunc) (net.IP, error) {
	return p.lookup(context.Background(), host, "test", []string{"10.0.0.53"}, dial)
}

func TestDNSUDPTimeoutFallsBackToTCPAndSkipsCoolingUDP(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	p := testDNSPool()
	start := time.Now()
	ip, e := poolLookup(p, "first.example", f.dial)
	if e != nil || ip.String() != "10.20.30.40" {
		t.Fatalf("fallback: %v %v", ip, e)
	}
	if time.Since(start) > time.Second {
		t.Fatal("UDP budget did not bound fallback")
	}
	if f.udpCalls.Load() != 1 || f.tcpCalls.Load() != 1 {
		t.Fatalf("calls udp=%d tcp=%d", f.udpCalls.Load(), f.tcpCalls.Load())
	}
	if _, e := poolLookup(p, "second.example", f.dial); e != nil {
		t.Fatal(e)
	}
	if f.udpCalls.Load() != 1 || f.tcpCalls.Load() != 2 {
		t.Fatalf("cooldown calls udp=%d tcp=%d", f.udpCalls.Load(), f.tcpCalls.Load())
	}
}

func TestDNSBackoffAndUDPRecovery(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	p := testDNSPool()
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	p.now = func() time.Time { return time.Unix(0, clock.Load()) }
	for _, delay := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 300 * time.Second} {
		if _, e := poolLookup(p, "retry.example", f.dial); e != nil {
			t.Fatal(e)
		}
		h := p.servers["10.0.0.53"]
		if got := h.udpRetryAt.Sub(p.now()); got != delay {
			t.Fatalf("cooldown=%v want %v", got, delay)
		}
		clock.Add(int64(delay))
	}
	f.udpMode.Store(dnsAnswer)
	tcpBefore := f.tcpCalls.Load()
	if _, e := poolLookup(p, "recovered.example", f.dial); e != nil {
		t.Fatal(e)
	}
	h := p.servers["10.0.0.53"]
	if !h.udpHealthy || !h.udpRetryAt.IsZero() || h.udpFailures != 0 {
		t.Fatal("UDP recovery did not reset state")
	}
	if _, e := poolLookup(p, "normal.example", f.dial); e != nil {
		t.Fatal(e)
	}
	if f.tcpCalls.Load() != tcpBefore {
		t.Fatal("recovered UDP still uses TCP")
	}
}

func TestDNSConcurrentLookupsShareOneUDPRecoveryProbe(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	p := testDNSPool()
	p.policy.udpTimeout = 400 * time.Millisecond
	p.candidates("test", []string{"10.0.0.53"})
	p.mu.Lock()
	health := p.servers["10.0.0.53"]
	health.udpHealthy = false
	health.udpFailures = 1
	health.udpRetryAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	first := make(chan error, 1)
	go func() { _, e := poolLookup(p, "probe.example", f.dial); first <- e }()
	select {
	case <-f.udpEntered:
	case <-time.After(time.Second):
		t.Fatal("UDP probe did not start")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := poolLookup(p, fmt.Sprintf("parallel%d.example", i), f.dial)
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if f.udpCalls.Load() != 1 {
		t.Fatalf("concurrent UDP probes=%d", f.udpCalls.Load())
	}
	if e := <-first; e != nil {
		t.Fatal(e)
	}
	// The same single-probe rule applies after a failed UDP transport's cooldown.
	p.mu.Lock()
	h := p.servers["10.0.0.53"]
	h.udpRetryAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	wg = sync.WaitGroup{}
	errs = make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := poolLookup(p, fmt.Sprintf("retryparallel%d.example", i), f.dial)
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if f.udpCalls.Load() != 2 {
		t.Fatalf("expired-cooldown UDP probes=%d", f.udpCalls.Load())
	}
}

func TestDNSNegativeAnswersAndFakeIPDoNotDisableUDP(t *testing.T) {
	for _, mode := range []int32{dnsNegative, dnsFake, dnsServfail} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			f := newDNSFixture(t)
			f.udpMode.Store(mode)
			f.tcpMode.Store(mode)
			p := testDNSPool()
			if _, e := poolLookup(p, "negative.example", f.dial); e == nil {
				t.Fatal("expected unusable/negative answer")
			}
			h := p.servers["10.0.0.53"]
			if !h.udpHealthy || !h.udpRetryAt.IsZero() || !h.serverRetryAt.IsZero() {
				t.Fatal("valid reply marked unavailable")
			}
			if mode != dnsServfail && f.tcpCalls.Load() != 0 {
				t.Fatal("negative/fake answer retried over TCP")
			}
		})
	}
}

func TestDNSTruncationUsesTCPWithoutCoolingUDP(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsTruncated)
	p := testDNSPool()
	ip, e := poolLookup(p, "truncated.example", f.dial)
	if e != nil || ip.String() != "10.20.30.40" {
		t.Fatalf("%v %v", ip, e)
	}
	h := p.servers["10.0.0.53"]
	if !h.udpHealthy || !h.udpRetryAt.IsZero() {
		t.Fatal("truncation cooled UDP")
	}
	if f.tcpCalls.Load() != 1 {
		t.Fatalf("TCP calls=%d", f.tcpCalls.Load())
	}
}

func TestDNSBothTransportsFailSkipServerThenProbeAgain(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	p.now = func() time.Time { return time.Unix(0, clock.Load()) }
	var failedCalls atomic.Int32
	var restored atomic.Bool
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "10.0.0.1:") && !restored.Load() {
			failedCalls.Add(1)
			return nil, errors.New("synthetic unavailable DNS")
		}
		return f.dial(ctx, network, address)
	}
	lookup := func() (net.IP, error) {
		return p.lookup(context.Background(), "pool.example", "test", []string{"10.0.0.1", "10.0.0.2"}, dial)
	}
	if _, e := lookup(); e != nil {
		t.Fatal(e)
	}
	first := failedCalls.Load()
	if first == 0 {
		t.Fatal("primary was not attempted")
	}
	if _, e := lookup(); e != nil {
		t.Fatal(e)
	}
	if failedCalls.Load() != first {
		t.Fatal("unavailable primary repeatedly attempted")
	}
	clock.Add(int64(30 * time.Second))
	restored.Store(true)
	udpBefore := f.udpCalls.Load()
	if _, e := lookup(); e != nil {
		t.Fatal(e)
	}
	h := p.servers["10.0.0.1"]
	if !h.serverRetryAt.IsZero() || !h.udpHealthy || f.udpCalls.Load() != udpBefore+1 {
		t.Fatal("primary was not probed/recovered before backup")
	}
}

func TestDNSAllServersCoolingFailFast(t *testing.T) {
	p := testDNSPool()
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("offline")
	}
	if _, e := poolLookup(p, "offline.example", dial); e == nil {
		t.Fatal("expected failure")
	}
	before := calls.Load()
	if _, e := poolLookup(p, "stilloffline.example", dial); !errors.Is(e, errDNSCoolingDown) {
		t.Fatalf("%v", e)
	}
	if calls.Load() != before {
		t.Fatal("cooling pool made new network requests")
	}
}

func TestDNSCallerCancellationDoesNotPoisonHealth(t *testing.T) {
	p := testDNSPool()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	var once sync.Once
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { _, e := p.lookup(ctx, "cancel.example", "test", []string{"10.0.0.53"}, dial); done <- e }()
	<-entered
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatalf("%v", e)
	}
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		h := p.servers["10.0.0.53"]
		ready := !h.udpProbe && !h.serverProbe
		failed := h.udpFailures != 0 || h.serverFailures != 0
		p.mu.Unlock()
		if failed {
			t.Fatal("caller cancellation changed failure state")
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled worker did not release probe")
		}
		time.Sleep(time.Millisecond)
	}
	f := newDNSFixture(t)
	if _, e := poolLookup(p, "next.example", f.dial); e != nil {
		t.Fatal(e)
	}
	if f.udpCalls.Load() != 1 || f.tcpCalls.Load() != 0 {
		t.Fatal("canceled probe prevented UDP retry")
	}
}

func TestDNSRoutingScopeResetsHealth(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	p := testDNSPool()
	if _, e := poolLookup(p, "old.example", f.dial); e != nil {
		t.Fatal(e)
	}
	old := p.servers["10.0.0.53"]
	f.udpMode.Store(dnsAnswer)
	if _, e := p.lookup(context.Background(), "new.example", "new-session", []string{"10.0.0.53"}, f.dial); e != nil {
		t.Fatal(e)
	}
	if p.servers["10.0.0.53"] == old || f.udpCalls.Load() != 2 {
		t.Fatal("new scope retained old UDP cooldown")
	}
}

type dnsProtocolTunnel struct {
	fixture        *dnsFixture
	t              *testing.T
	udpApp, tcpApp string
	tcpAllowed     bool
}

func (d *dnsProtocolTunnel) DialUDP(ctx context.Context, ip string, port int, app, domain string) (net.Conn, error) {
	if ip != "10.0.0.53" || port != 53 || app != d.udpApp || domain != "" {
		d.t.Errorf("UDP authorization: %s:%d %s %s", ip, port, app, domain)
	}
	return d.fixture.dial(ctx, "udp", "")
}
func (d *dnsProtocolTunnel) Dial(ctx context.Context, ip string, port int, app, domain string) (net.Conn, error) {
	if !d.tcpAllowed {
		d.t.Error("unauthorized TCP dial")
	}
	if ip != "10.0.0.53" || port != 53 || app != d.tcpApp || domain != "" {
		d.t.Errorf("TCP authorization: %s:%d %s %s", ip, port, app, domain)
	}
	return d.fixture.dial(ctx, "tcp", "")
}
func protocolResolver(t *testing.T, f *dnsFixture, allowTCP bool) *Resolver {
	cred := &session.Credential{SID: "test-session", DNS: []string{"10.0.0.53"}, Policy: &sdpc.Resource{IPRules: []sdpc.IPRule{{IP: net.ParseIP("10.0.0.53"), AppID: "udp-app", Proto: "udp", Port: sdpc.PortRange{Min: 53, Max: 53}}}}}
	if allowTCP {
		cred.Policy.IPRules = append(cred.Policy.IPRules, sdpc.IPRule{IP: net.ParseIP("10.0.0.53"), AppID: "tcp-app", Proto: "tcp", Port: sdpc.PortRange{Min: 53, Max: 53}})
	}
	r := New(&staticProvider{cred: cred}, &dnsProtocolTunnel{fixture: f, t: t, udpApp: "udp-app", tcpApp: "tcp-app", tcpAllowed: allowTCP})
	r.stages = nil
	r.tunnelDNS.policy.udpTimeout = 50 * time.Millisecond
	return r
}
func TestTunnelDNSFallbackUsesSeparateTCPAuthorization(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	r := protocolResolver(t, f, true)
	got, e := r.LookupHost(context.Background(), "internal.example")
	if e != nil || len(got) != 1 || got[0] != "10.20.30.40" {
		t.Fatalf("%v %v", got, e)
	}
	if f.tcpCalls.Load() != 1 {
		t.Fatal("TCP fallback missing")
	}
}
func TestTunnelDNSFallbackRejectsUnauthorizedTCP(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	r := protocolResolver(t, f, false)
	if _, e := r.LookupHost(context.Background(), "internal.example"); e == nil {
		t.Fatal("expected unauthorized fallback failure")
	}
	if f.tcpCalls.Load() != 0 {
		t.Fatal("TCP used UDP application's authorization")
	}
}
func TestPublicDNSNegativeStillFallsBackToTunnel(t *testing.T) {
	public := newDNSFixture(t)
	public.udpMode.Store(dnsNegative)
	private := newDNSFixture(t)
	cred := &session.Credential{SID: "test", DNS: []string{"10.0.0.53"}, Policy: &sdpc.Resource{IPRules: []sdpc.IPRule{{IP: net.ParseIP("10.0.0.53"), AppID: "udp-app", Proto: "udp", Port: sdpc.PortRange{Min: 53, Max: 53}}}}}
	r := NewWithDialerOptions(&staticProvider{cred: cred}, &dnsProtocolTunnel{fixture: private, t: t, udpApp: "udp-app"}, public.dial, true)
	got, e := r.LookupHost(context.Background(), "split.example")
	if e != nil || len(got) != 1 || got[0] != "10.20.30.40" {
		t.Fatalf("%v %v", got, e)
	}
	if public.tcpCalls.Load() != 0 || private.udpCalls.Load() != 1 {
		t.Fatal("wrong negative-answer fallback path")
	}
}
func TestTunnelDNSScopeChangesWithSessionRoutesAndProtocols(t *testing.T) {
	f := newDNSFixture(t)
	r := protocolResolver(t, f, true)
	cred := r.provider.(*staticProvider).cred
	before := r.tunnelDNSScope(cred)
	cred.SID = "new"
	if r.tunnelDNSScope(cred) == before {
		t.Fatal("SID not scoped")
	}
	before = r.tunnelDNSScope(cred)
	cred.Gateways = []string{"new-gateway:441"}
	if r.tunnelDNSScope(cred) == before {
		t.Fatal("gateway not scoped")
	}
	before = r.tunnelDNSScope(cred)
	cred.Policy.IPRules[1].AppID = "new-tcp-app"
	if r.tunnelDNSScope(cred) == before {
		t.Fatal("TCP policy not scoped")
	}
}

func TestDNSIdenticalConcurrentQueriesShareTCP(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsDrop)
	p := testDNSPool()
	if _, e := poolLookup(p, "establish-cooldown.example", f.dial); e != nil {
		t.Fatal(e)
	}
	tcpBefore := f.tcpCalls.Load()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return f.dial(ctx, network, address)
	}
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, e := poolLookup(p, "same.example", dial); errs <- e }()
	}
	<-entered
	deadline := time.After(time.Second)
	for {
		p.mu.Lock()
		waiters := 0
		for _, call := range p.flights {
			waiters += call.waiters
		}
		p.mu.Unlock()
		if waiters == n {
			break
		}
		select {
		case <-deadline:
			t.Fatal("waiters did not join")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	for i := 0; i < n; i++ {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	if got := f.tcpCalls.Load() - tcpBefore; got != 1 {
		t.Fatalf("shared TCP connections=%d", got)
	}
}

func TestDNSCancelOneWaiterKeepsSharedLookupAlive(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return f.dial(ctx, network, address)
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, e := p.lookup(ctx, "shared.example", "test", []string{"10.0.0.53"}, dial); first <- e }()
	<-entered
	go func() { _, e := poolLookup(p, "shared.example", dial); second <- e }()
	deadline := time.After(time.Second)
	for {
		p.mu.Lock()
		waiters := 0
		for _, call := range p.flights {
			waiters += call.waiters
		}
		p.mu.Unlock()
		if waiters == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("second waiter did not join")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if e := <-first; !errors.Is(e, context.Canceled) {
		t.Fatalf("canceled waiter: %v", e)
	}
	close(release)
	if e := <-second; e != nil {
		t.Fatalf("remaining waiter: %v", e)
	}
	if f.udpCalls.Load() != 1 || f.tcpCalls.Load() != 0 {
		t.Fatal("shared lookup transport changed after one cancellation")
	}
}

func TestDNSCaseInsensitiveReplyRemainsUDPHealthy(t *testing.T) {
	f := newDNSFixture(t)
	f.udpMode.Store(dnsLowercase)
	p := testDNSPool()
	if _, e := poolLookup(p, "MiXeD.ExAmPlE", f.dial); e != nil {
		t.Fatal(e)
	}
	h := p.servers["10.0.0.53"]
	if !h.udpHealthy || !h.udpRetryAt.IsZero() {
		t.Fatal("case-insensitive valid reply cooled UDP")
	}
}

func TestDNSStaleUDPCompletionCannotClearNewFailure(t *testing.T) {
	p := testDNSPool()
	h := &dnsServerHealth{udpHealthy: true}
	first, _ := p.beginUDP(h)
	second, _ := p.beginUDP(h)
	p.finishUDP(h, first, false, false)
	retry := h.udpRetryAt
	p.finishUDP(h, second, true, false)
	if h.udpHealthy || h.udpRetryAt != retry || h.udpFailures != 1 {
		t.Fatal("stale successful request cleared newer failure")
	}
}

func TestDNSFreshUDPOnlyServerSupportsDifferentConcurrentNames(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	p.policy.udpTimeout = time.Second
	const n = 16
	var entered atomic.Int32
	ready := make(chan struct{})
	release := make(chan struct{})
	errs := make(chan error, n)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" {
			return nil, errors.New("TCP not authorized")
		}
		if entered.Add(1) == n {
			close(ready)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return f.dial(ctx, network, address)
	}
	for i := 0; i < n; i++ {
		go func(i int) { _, e := poolLookup(p, fmt.Sprintf("udp-only%d.example", i), dial); errs <- e }(i)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("fresh UDP queries were incorrectly switched to TCP")
	}
	close(release)
	for i := 0; i < n; i++ {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	if f.udpCalls.Load() != n || f.tcpCalls.Load() != 0 {
		t.Fatal("working UDP-only DNS lost concurrent queries")
	}
}
