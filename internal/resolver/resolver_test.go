package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"geektrust/internal/sdpc"
	"geektrust/internal/session"
)

func TestIsFakeIP(t *testing.T) {
	cases := map[string]bool{
		"198.18.0.1":     true,
		"198.18.10.205":  true,
		"198.19.255.255": true,
		"198.17.0.1":     false,
		"198.20.0.1":     false,
		"10.15.45.163":   false,
		"8.8.8.8":        false,
	}
	for s, want := range cases {
		if got := IsFakeIP(net.ParseIP(s)); got != want {
			t.Errorf("IsFakeIP(%s) = %v, want %v", s, got, want)
		}
	}
	if IsFakeIP(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 must not be flagged as fake-ip")
	}
}

func TestNewStages(t *testing.T) {
	r := New(nil, nil)
	if len(r.stages) != 2 {
		t.Fatalf("stages = %d, want 2 (public defaults + system)", len(r.stages))
	}
}

func TestRouteDNSResultPrefersIPPolicy(t *testing.T) {
	ip := net.ParseIP("180.101.49.44")
	policy := &sdpc.Resource{
		IPRules: []sdpc.IPRule{{
			Net:   &net.IPNet{IP: net.IPv4(128, 0, 0, 0), Mask: net.CIDRMask(1, 32)},
			AppID: "ip-app",
			Port:  sdpc.PortRange{Min: 1, Max: 65535},
			Proto: "all",
		}},
		SuffixRules: []sdpc.SuffixRule{{
			Suffix: ".com",
			AppID:  "suffix-app",
			Port:   sdpc.PortRange{Min: 1, Max: 65535},
			Proto:  "all",
		}},
	}
	cred := &session.Credential{Policy: policy, AppID: "fallback-app"}

	got := routeDNSResult(cred, "www.baidu.com", 443, ip, "tcp")
	if got.IP != "180.101.49.44" || got.AppID != "ip-app" || got.Domain != "" {
		t.Fatalf("IP-authorized resolution = %+v", got)
	}

	policy.IPRules = nil
	got = routeDNSResult(cred, "www.baidu.com", 443, ip, "tcp")
	if got.AppID != "suffix-app" || got.Domain != "www.baidu.com" {
		t.Fatalf("suffix fallback resolution = %+v", got)
	}

	policy.SuffixRules = nil
	got = routeDNSResult(cred, "www.baidu.com", 443, ip, "tcp")
	if got.AppID != "fallback-app" || got.Domain != "" {
		t.Fatalf("default resolution = %+v", got)
	}
}

type staticProvider struct {
	cred *session.Credential
}

func (p *staticProvider) Credential(context.Context) (*session.Credential, error) {
	return p.cred, nil
}

func (*staticProvider) InvalidateIfCurrent(*session.Credential) bool { return false }

func TestResolveUDPUsesUDPPolicy(t *testing.T) {
	policy := &sdpc.Resource{IPRules: []sdpc.IPRule{
		{IP: net.ParseIP("10.0.0.53"), AppID: "tcp-app", Port: sdpc.PortRange{Min: 53, Max: 53}, Proto: "tcp"},
		{IP: net.ParseIP("10.0.0.53"), AppID: "udp-app", Port: sdpc.PortRange{Min: 53, Max: 53}, Proto: "udp"},
	}}
	r := New(&staticProvider{cred: &session.Credential{Policy: policy, AppID: "fallback"}}, nil)

	udp, err := r.ResolveUDP(context.Background(), "10.0.0.53", 53)
	if err != nil {
		t.Fatal(err)
	}
	if udp.AppID != "udp-app" {
		t.Fatalf("UDP resolution = %+v", udp)
	}
	tcp, err := r.Resolve(context.Background(), "10.0.0.53", 53)
	if err != nil {
		t.Fatal(err)
	}
	if tcp.AppID != "tcp-app" {
		t.Fatalf("TCP resolution = %+v", tcp)
	}
}

type localDNSTunnel struct {
	server *net.UDPAddr
	ip     string
	appID  string
}

func (d *localDNSTunnel) Dial(context.Context, string, int, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TCP DNS fallback")
}

func (d *localDNSTunnel) DialUDP(_ context.Context, ip string, _ int, appID, _ string) (net.Conn, error) {
	d.ip, d.appID = ip, appID
	return net.DialUDP("udp4", nil, d.server)
}

func TestResolveFallsBackToControllerDNSThroughTunnel(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, client, err := server.ReadFromUDP(buf)
		if err != nil {
			served <- err
			return
		}
		questionEnd := 12
		for questionEnd < n && buf[questionEnd] != 0 {
			questionEnd += int(buf[questionEnd]) + 1
		}
		questionEnd += 5 // root label plus QTYPE and QCLASS
		if questionEnd > n {
			served <- errors.New("malformed DNS question")
			return
		}
		response := append([]byte(nil), buf[:questionEnd]...)
		response[2], response[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(response[6:8], 1)
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		response = append(response,
			0xc0, 0x0c, // compressed owner name
			0x00, 0x01, 0x00, 0x01, // A, IN
			0x00, 0x00, 0x00, 0x3c, // TTL
			0x00, 0x04, 10, 20, 30, 40,
		)
		_, err = server.WriteToUDP(response, client)
		served <- err
	}()

	cred := &session.Credential{
		DNS:    []string{"10.13.87.17"},
		Policy: &sdpc.Resource{},
		AppID:  "fallback-app",
	}
	tunnel := &localDNSTunnel{server: server.LocalAddr().(*net.UDPAddr)}
	r := New(&staticProvider{cred: cred}, tunnel)
	r.stages = nil // isolate the split-horizon fallback from real network DNS
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := r.Resolve(ctx, "netinfo.shanghaitech.edu.cn", 443)
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != "10.20.30.40" || got.AppID != "fallback-app" {
		t.Fatalf("resolution = %+v", got)
	}
	if tunnel.ip != "10.13.87.17" || tunnel.appID != "fallback-app" {
		t.Fatalf("DNS tunnel target = %s appID=%s", tunnel.ip, tunnel.appID)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestResolveRejectsGatewayLoops(t *testing.T) {
	cred := &session.Credential{
		Gateways: []string{"10.13.90.147:441", "vpn.example:441"},
		AppID:    "fallback-app",
		Policy: &sdpc.Resource{DomainRules: []sdpc.DomainRule{{
			Domain: "mapped.example",
			IP:     "10.13.90.147",
			AppID:  "mapped-app",
			Port:   sdpc.PortRange{Min: 441, Max: 441},
			Proto:  "tcp",
		}}},
	}
	r := New(&staticProvider{cred: cred}, nil)

	for _, host := range []string{"10.13.90.147", "vpn.example", "mapped.example"} {
		if _, err := r.Resolve(context.Background(), host, 441); !errors.Is(err, ErrGatewayLoop) {
			t.Errorf("Resolve(%q, 441) error = %v, want ErrGatewayLoop", host, err)
		}
	}

	got, err := r.Resolve(context.Background(), "10.13.90.147", 443)
	if err != nil {
		t.Fatalf("same gateway IP on another port: %v", err)
	}
	if got.IP != "10.13.90.147" || got.AppID != "fallback-app" {
		t.Fatalf("non-gateway endpoint resolution = %+v", got)
	}
}
