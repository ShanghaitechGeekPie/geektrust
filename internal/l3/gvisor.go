package l3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"geektrust/internal/tunnel"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID               tcpip.NICID = 1
	tunnelMTU                       = 1400
	tcpHandshakeTimeout             = 8 * time.Second
	outboundQueueLen                = 1024
	// A closed endpoint can spend 60s in FIN_WAIT_2 before the peer FIN, then
	// another 60s in TIME_WAIT. Keep the gateway route through both default
	// gVisor intervals, with margin for scheduling and delayed packets.
	connectionLinger = tcp.DefaultTCPLingerTimeout + tcp.DefaultTCPTimeWaitTimeout + 10*time.Second
)

type dataSender interface {
	SendData(token string, deadline time.Time, packets ...[]byte) error
}

type dataRoute struct {
	token    string
	deadline time.Time
}

// linkEndpoint carries complete IPv4 packets between gVisor and one aTrust
// tunnel. The route table binds each gVisor source port to the connectToken
// returned by per-connection authentication.
type linkEndpoint struct {
	tun    dataSender
	logger *slog.Logger

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	routes     map[uint16]dataRoute
	closed     bool
}

func (e *linkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
func (e *linkEndpoint) MTU() uint32                          { return tunnelMTU }
func (e *linkEndpoint) SetMTU(uint32)                        {}
func (e *linkEndpoint) MaxHeaderLength() uint16              { return 0 }
func (e *linkEndpoint) LinkAddress() tcpip.LinkAddress       { return "" }
func (e *linkEndpoint) SetLinkAddress(tcpip.LinkAddress)     {}
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (e *linkEndpoint) Wait()                                   {}
func (e *linkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *linkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *linkEndpoint) Close()                                  {}
func (e *linkEndpoint) SetOnCloseAction(func())                 {}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
}

func (e *linkEndpoint) IsAttached() bool {
	e.mu.RLock()
	attached := e.dispatcher != nil
	e.mu.RUnlock()
	return attached
}

// WritePackets is gVisor's uplink. Consecutive packets for one connection are
// packed into one aTrust frame, reducing TLS records and serialized writes.
func (e *linkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	type outbound struct {
		route    dataRoute
		data     []byte
		position int
	}
	packetBuffers := list.AsSlice()
	if len(packetBuffers) == 1 {
		route, data, err := e.routePacket(packetBuffers[0])
		if err != nil {
			return 1, nil
		}
		if routeExpired(route) {
			return 1, nil
		}
		if err := e.tun.SendData(route.token, route.deadline, data); err != nil {
			if !route.deadline.IsZero() && errors.Is(err, os.ErrDeadlineExceeded) {
				return 1, nil
			}
			if errors.Is(err, tunnel.ErrTunnelDead) || errors.Is(err, net.ErrClosed) {
				return 1, nil
			}
			e.logger.Debug("IP stack uplink failed", "err", err)
			return 0, &tcpip.ErrAborted{}
		}
		return 1, nil
	}

	packets := make([]outbound, 0, len(packetBuffers))
	for position, packetBuffer := range packetBuffers {
		route, data, err := e.routePacket(packetBuffer)
		if err != nil {
			continue
		}
		packets = append(packets, outbound{route: route, data: data, position: position})
	}
	if len(packets) == 0 {
		return len(packetBuffers), nil
	}
	sent := 0
	for sent < len(packets) {
		route := packets[sent].route
		end := sent + 1
		for end < len(packets) && end-sent < 255 &&
			packets[end].position == packets[end-1].position+1 &&
			packets[end].route == route {
			end++
		}
		if routeExpired(route) {
			sent = end
			continue
		}
		batch := make([][]byte, end-sent)
		for i := range batch {
			batch[i] = packets[sent+i].data
		}
		if err := e.tun.SendData(route.token, route.deadline, batch...); err != nil {
			if !route.deadline.IsZero() && errors.Is(err, os.ErrDeadlineExceeded) {
				sent = end
				continue
			}
			if errors.Is(err, tunnel.ErrTunnelDead) || errors.Is(err, net.ErrClosed) {
				return len(packetBuffers), nil
			}
			e.logger.Debug("IP stack uplink failed", "err", err)
			return packets[sent].position, &tcpip.ErrAborted{}
		}
		sent = end
	}
	return len(packetBuffers), nil
}

func routeExpired(route dataRoute) bool {
	return !route.deadline.IsZero() && !time.Now().Before(route.deadline)
}

func (e *linkEndpoint) routePacket(packet *stack.PacketBuffer) (dataRoute, []byte, tcpip.Error) {
	data := flattenPacket(packet)
	port, ok := ipSourcePort(data)
	if !ok {
		return dataRoute{}, nil, &tcpip.ErrMalformedHeader{}
	}
	e.mu.RLock()
	route, ok := e.routes[port]
	e.mu.RUnlock()
	if !ok || route.token == "" {
		return dataRoute{}, nil, &tcpip.ErrInvalidEndpointState{}
	}
	return route, data, nil
}

func flattenPacket(packet *stack.PacketBuffer) []byte {
	views, offset := packet.AsViewList()
	first := views.Front()
	if first == nil {
		return nil
	}
	if first.Next() == nil {
		data := first.AsSlice()
		if offset > len(data) {
			return nil
		}
		return data[offset:]
	}
	data := make([]byte, packet.Size())
	written := 0
	for view := first; view != nil; view = view.Next() {
		part := view.AsSlice()
		if offset >= len(part) {
			offset -= len(part)
			continue
		}
		part = part[offset:]
		offset = 0
		written += copy(data[written:], part)
	}
	return data[:written]
}

func ipSourcePort(packet []byte) (uint16, bool) {
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize {
		return 0, false
	}
	minTransportSize := 0
	switch packet[9] {
	case uint8(header.TCPProtocolNumber):
		minTransportSize = header.TCPMinimumSize
	case uint8(header.UDPProtocolNumber):
		minTransportSize = header.UDPMinimumSize
	default:
		return 0, false
	}
	if len(packet) < ihl+minTransportSize {
		return 0, false
	}
	return uint16(packet[ihl])<<8 | uint16(packet[ihl+1]), true
}

func (e *linkEndpoint) DeliverPacket(packet []byte) {
	e.mu.RLock()
	dispatcher := e.dispatcher
	e.mu.RUnlock()
	if dispatcher == nil {
		return
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, packetBuffer)
	packetBuffer.DecRef()
}

func (e *linkEndpoint) addRoute(port uint16) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.routes[port] = dataRoute{}
	return true
}

func (e *linkEndpoint) updateRoute(port uint16, route dataRoute) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	if _, ok := e.routes[port]; !ok {
		return false
	}
	e.routes[port] = route
	return true
}

func (e *linkEndpoint) removeRoute(port uint16) bool {
	e.mu.Lock()
	_, ok := e.routes[port]
	delete(e.routes, port)
	e.mu.Unlock()
	return ok
}

func (e *linkEndpoint) closeRoutes() []uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	ports := make([]uint16, 0, len(e.routes))
	for port := range e.routes {
		ports = append(ports, port)
	}
	clear(e.routes)
	return ports
}

type tcpStack struct {
	tun      *tunnel.Tunnel
	endpoint *linkEndpoint
	stack    *stack.Stack
	vip      net.IP
	close    sync.Once

	timerMu   sync.Mutex
	timers    map[uint16]*time.Timer
	destroyed bool
}

func newTCPStack(tun *tunnel.Tunnel, logger *slog.Logger) (*tcpStack, error) {
	vip := tun.VIP().To4()
	if vip == nil {
		return nil, errors.New("IP stack requires an IPv4 tunnel address")
	}
	endpoint := &linkEndpoint{
		tun:    tun,
		logger: logger,
		routes: make(map[uint16]dataRoute),
	}
	gstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: true,
	})
	qdisc := fifo.New(endpoint, 1, outboundQueueLen)
	if err := gstack.CreateNICWithOptions(nicID, endpoint, stack.NICOptions{QDisc: qdisc}); err != nil {
		qdisc.Close()
		gstack.Destroy()
		return nil, fmt.Errorf("create IP stack NIC: %s", err)
	}
	addr := tcpip.AddrFromSlice(vip)
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 32},
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := gstack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("add IP stack address: %s", err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := gstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("enable TCP SACK: %s", err)
	}
	moderateReceiveBuffer := tcpip.TCPModerateReceiveBufferOption(true)
	if err := gstack.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateReceiveBuffer); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("enable TCP receive-buffer tuning: %s", err)
	}
	congestionControl := tcpip.CongestionControlOption("cubic")
	if err := gstack.SetTransportProtocolOption(tcp.ProtocolNumber, &congestionControl); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("select TCP congestion control: %s", err)
	}
	gstack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	return &tcpStack{
		tun:      tun,
		endpoint: endpoint,
		stack:    gstack,
		vip:      vip,
		timers:   make(map[uint16]*time.Timer),
	}, nil
}

func (s *tcpStack) dial(ctx context.Context, remote net.IP, srcPort, dstPort uint16, deadline time.Time) (*gonet.TCPConn, error) {
	localAddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(s.vip), Port: srcPort}
	remoteAddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(remote.To4()), Port: dstPort}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	return gonet.DialTCPWithBind(dialCtx, s.stack, localAddr, remoteAddr, ipv4.ProtocolNumber)
}

func (s *tcpStack) dialUDP(ctx context.Context, remote net.IP, srcPort, dstPort uint16) (*gonet.UDPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	localAddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(s.vip), Port: srcPort}
	remoteAddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(remote.To4()), Port: dstPort}
	return gonet.DialUDP(s.stack, &localAddr, &remoteAddr, ipv4.ProtocolNumber)
}

func (s *tcpStack) release(port uint16) {
	s.timerMu.Lock()
	timer := s.timers[port]
	delete(s.timers, port)
	s.timerMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if s.endpoint.removeRoute(port) {
		s.tun.UnregisterConn(port)
	}
}

func (s *tcpStack) releaseLater(port uint16) {
	s.timerMu.Lock()
	if s.destroyed || !s.tun.Alive() {
		s.timerMu.Unlock()
		s.release(port)
		return
	}
	s.timers[port] = time.AfterFunc(connectionLinger, func() { s.release(port) })
	s.timerMu.Unlock()
}

func (s *tcpStack) destroy() {
	s.close.Do(func() {
		s.timerMu.Lock()
		s.destroyed = true
		timers := s.timers
		s.timers = make(map[uint16]*time.Timer)
		s.timerMu.Unlock()
		for _, timer := range timers {
			timer.Stop()
		}

		ports := s.endpoint.closeRoutes()
		s.stack.Destroy()
		for _, port := range ports {
			s.tun.UnregisterConn(port)
		}
	})
}

// managedTCPConn retains the authenticated port route after Close so gVisor
// can complete FIN/TIME_WAIT processing. CloseWrite remains a real TCP
// half-close through the embedded gonet.TCPConn.
type managedTCPConn struct {
	*gonet.TCPConn
	stack     *tcpStack
	port      uint16
	closeOnce sync.Once
}

func (c *managedTCPConn) Close() error {
	err := c.TCPConn.Close()
	c.closeOnce.Do(func() { c.stack.releaseLater(c.port) })
	return err
}

type managedUDPConn struct {
	*gonet.UDPConn
	stack     *tcpStack
	port      uint16
	closeOnce sync.Once
}

func (c *managedUDPConn) Close() error {
	err := c.UDPConn.Close()
	c.closeOnce.Do(func() { c.stack.release(c.port) })
	return err
}
