package sdpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Resource is the parsed clientResource routing policy: which appId
// authorizes which destination (domain/internal IP/CIDR/range × port
// range), plus gateway lines and DNS servers.
type Resource struct {
	// DomainRules map exact domains to internal endpoints.
	DomainRules []DomainRule
	// SuffixRules map TLD wildcards ("*.com" → ".com") to apps; the dial
	// target is the DNS-resolved address of the host.
	SuffixRules []SuffixRule
	// IPRules match destination IPs (exact/CIDR/range × port range).
	IPRules []IPRule
	// Gateways are the node group access addresses (host:port).
	Gateways []string
	// DNS are controller-pushed resolver addresses, if any.
	DNS []string
}

// DomainRule is one domain entry of an app's addressList.
type DomainRule struct {
	Domain string
	IP     string // first internal IP of the same app: the dial target
	AppID  string
	Port   PortRange
	Proto  string // tcp / udp / all
}

// SuffixRule is one "*.tld" entry of an app's addressList.
type SuffixRule struct {
	Suffix string // ".com", ".cn", …
	AppID  string
	Port   PortRange
	Proto  string
}

// IPRule is one IP/CIDR/range entry of an app's addressList.
type IPRule struct {
	IP    net.IP     // exact address
	Net   *net.IPNet // CIDR prefix
	IPMin net.IP     // inclusive range start (with IPMax)
	IPMax net.IP
	AppID string
	Port  PortRange
	Proto string
}

// PortRange is an inclusive port interval.
type PortRange struct{ Min, Max int }

// Contains reports whether port falls in the range.
func (r PortRange) Contains(port int) bool { return port >= r.Min && port <= r.Max }

func allPorts() PortRange { return PortRange{0, 65535} }

// MatchDomain returns the TCP rule authorizing domain:port.
func (r *Resource) MatchDomain(domain string, port int) (DomainRule, bool) {
	return r.MatchDomainProtocol(domain, port, "tcp")
}

// MatchDomainProtocol returns the rule authorizing domain:port for protocol.
// When several rules cover the port, the narrowest port range wins; ties keep
// appList order.
func (r *Resource) MatchDomainProtocol(domain string, port int, protocol string) (DomainRule, bool) {
	domain = normalizeHost(domain)
	var best DomainRule
	bestWidth := 1 << 30
	found := false
	for _, rule := range r.DomainRules {
		if rule.Domain != domain || !rule.Port.Contains(port) || !protocolCompatible(rule.Proto, protocol) {
			continue
		}
		if width := rule.Port.Max - rule.Port.Min; !found || width < bestWidth {
			best, bestWidth, found = rule, width, true
		}
	}
	return best, found
}

// MatchSuffix returns the TCP rule whose TLD wildcard covers host:port.
func (r *Resource) MatchSuffix(host string, port int) (SuffixRule, bool) {
	return r.MatchSuffixProtocol(host, port, "tcp")
}

// MatchSuffixProtocol returns the rule whose TLD wildcard covers host:port
// for protocol. The longest suffix wins; ties keep appList order.
func (r *Resource) MatchSuffixProtocol(host string, port int, protocol string) (SuffixRule, bool) {
	host = normalizeHost(host)
	var best SuffixRule
	found := false
	for _, rule := range r.SuffixRules {
		if !strings.HasSuffix(host, rule.Suffix) || !rule.Port.Contains(port) || !protocolCompatible(rule.Proto, protocol) {
			continue
		}
		if !found || len(rule.Suffix) > len(best.Suffix) {
			best, found = rule, true
		}
	}
	return best, found
}

// normalizeHost lowercases a hostname and strips one trailing root dot.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// MatchIP returns the most specific TCP rule authorizing ip:port.
func (r *Resource) MatchIP(ip net.IP, port int) (IPRule, bool) {
	return r.MatchIPProtocol(ip, port, "tcp")
}

// MatchIPProtocol returns the most specific rule authorizing ip:port for
// protocol. Exact addresses win. CIDRs and ranges are compared by the number
// of addresses they cover; ties keep appList order.
func (r *Resource) MatchIPProtocol(ip net.IP, port int, protocol string) (IPRule, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return IPRule{}, false
	}
	var best IPRule
	bestExact := false
	bestSpan := ^uint64(0)
	found := false
	for _, rule := range r.IPRules {
		if !rule.Port.Contains(port) || !protocolCompatible(rule.Proto, protocol) {
			continue
		}
		exact := false
		span := ^uint64(0)
		switch {
		case rule.IP != nil:
			if rule.IP.Equal(ip4) {
				exact, span = true, 1
			}
		case rule.Net != nil:
			if rule.Net.Contains(ip4) {
				ones, bits := rule.Net.Mask.Size()
				if bits == 32 && ones >= 0 {
					span = uint64(1) << uint(32-ones)
				}
			}
		case rule.IPMin != nil && rule.IPMax != nil:
			min, max := rule.IPMin.To4(), rule.IPMax.To4()
			if min != nil && max != nil && bytes.Compare(min, max) <= 0 &&
				bytes.Compare(ip4, min) >= 0 && bytes.Compare(ip4, max) <= 0 {
				span = uint64(ipToU32(max)-ipToU32(min)) + 1
			}
		}
		if span == ^uint64(0) {
			continue
		}
		if !found || (exact && !bestExact) || (exact == bestExact && span < bestSpan) {
			best, bestExact, bestSpan, found = rule, exact, span, true
		}
	}
	return best, found
}

func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	return binary.BigEndian.Uint32(v4)
}

// AppIDFor returns the TCP appId authorizing ip:port, or fallback.
func (r *Resource) AppIDFor(ip net.IP, port int, fallback string) string {
	return r.AppIDForProtocol(ip, port, fallback, "tcp")
}

// AppIDForProtocol returns the appId authorizing ip:port for protocol, or
// fallback when no rule matches.
func (r *Resource) AppIDForProtocol(ip net.IP, port int, fallback, protocol string) string {
	if rule, ok := r.MatchIPProtocol(ip, port, protocol); ok {
		return rule.AppID
	}
	return fallback
}

func protocolCompatible(rule, requested string) bool {
	return rule == "" || rule == "all" || rule == requested
}

// clientResource mirrors the response parts geekTrust consumes. Decoding is
// case-insensitive, so untagged lowercase fields match the wire names.
type clientResource struct {
	AppList struct {
		Data struct {
			AppInfo []struct {
				Apps []struct {
					ID          string `json:"id"`
					AddressList []struct {
						Protocol string `json:"protocol"`
						Port     string `json:"port"`
						Host     string `json:"host"`
					} `json:"addressList"`
				} `json:"apps"`
			} `json:"appInfo"`
			Config struct {
				NodeGroupConf struct {
					NodeGroupList []struct {
						ID          string `json:"id"`
						AddressInfo []struct {
							Address string `json:"address"`
							Type    string `json:"type"`
						} `json:"addressInfo"`
					} `json:"nodeGroupList"`
				} `json:"nodeGroupConf"`
			} `json:"config"`
		} `json:"data"`
	} `json:"appList"`
	SDPPolicy struct {
		Data struct {
			ClientOption struct {
				DNSOption struct {
					FirstDNS  string `json:"firstDNS"`
					SecondDNS string `json:"secondDNS"`
				} `json:"dnsOption"`
				DNSOptionV2 struct {
					FirstDNS  string `json:"firstDNS"`
					SecondDNS string `json:"secondDNS"`
				} `json:"dnsOptionV2"`
			} `json:"clientOption"`
		} `json:"data"`
	} `json:"sdpPolicy"`
}

// ClientResource fetches the full resource policy via the unsigned browser
// path. The appList includes the catch-all apps (外网资源/内网资源段) that
// authorize nearly all internal/external destinations.
func (c *Client) ClientResource(ctx context.Context) (*Resource, error) {
	body := map[string]any{
		"resourceType": map[string]any{
			"sdpPolicy":       map[string]any{},
			"appList":         map[string]any{},
			"favoriteAppList": map[string]any{},
			"featureCenter":   map[string]any{},
			"uemSpace":        map[string]any{"params": map[string]string{"action": "login"}},
		},
	}
	var raw clientResource
	if err := c.doJSON(ctx, "POST", "/controller/v1/user/clientResource", url.Values{}, body, &raw); err != nil {
		return nil, err
	}
	return c.parseResource(&raw), nil
}

// parseResource builds the routing policy from the appList (incl. the
// catch-all apps 外网资源/内网资源段) and the gateway lines.
func (c *Client) parseResource(cr *clientResource) *Resource {
	res := &Resource{}
	for _, group := range cr.AppList.Data.AppInfo {
		for _, app := range group.Apps {
			var firstIP string
			type hostEntry struct {
				host  string
				port  PortRange
				proto string
			}
			var domains []hostEntry
			for _, entry := range app.AddressList {
				host := entry.Host
				if i := strings.IndexByte(host, '@'); i >= 0 {
					host = host[i+1:]
				}
				port := parsePortRange(entry.Port)
				proto := entry.Protocol
				switch {
				case host == "":
				case strings.HasPrefix(host, "*."):
					// TLD wildcard (*.com / *.cn …): suffix match; the dial
					// target is whatever the name resolves to.
					res.SuffixRules = append(res.SuffixRules, SuffixRule{
						Suffix: strings.ToLower(host[1:]), AppID: app.ID, Port: port, Proto: proto,
					})
				case strings.Contains(host, "*"):
					// Other wildcard shapes cannot be matched; skip.
				case isDottedIPv4(host):
					if firstIP == "" {
						firstIP = host
					}
					res.IPRules = append(res.IPRules, IPRule{
						IP: net.ParseIP(host).To4(), AppID: app.ID, Port: port, Proto: proto,
					})
				case strings.Contains(host, "/"):
					if _, ipNet, err := net.ParseCIDR(host); err == nil {
						res.IPRules = append(res.IPRules, IPRule{
							Net: ipNet, AppID: app.ID, Port: port, Proto: proto,
						})
					}
				case strings.Contains(host, "-"):
					parts := strings.SplitN(host, "-", 2)
					min, max := net.ParseIP(parts[0]), net.ParseIP(parts[1])
					if min != nil && max != nil {
						res.IPRules = append(res.IPRules, IPRule{
							IPMin: min, IPMax: max, AppID: app.ID, Port: port, Proto: proto,
						})
					}
				default:
					domains = append(domains, hostEntry{host, port, proto})
				}
			}
			// Domain → first internal IP of the same app, keeping each
			// domain entry's own authorized port range. MatchDomain picks
			// the most specific rule per (domain, port).
			if firstIP != "" {
				for _, d := range domains {
					res.DomainRules = append(res.DomainRules, DomainRule{
						Domain: normalizeHost(d.host), IP: firstIP, AppID: app.ID, Port: d.port, Proto: d.proto,
					})
				}
			}
		}
	}

	// Gateway lines: nodeGroupConf.nodeGroupList[].addressInfo[].address.
	// "{{sdpcHost}}" stands for the controller host.
	controllerHost := c.controllerHost()
	seen := make(map[string]bool)
	for _, ng := range cr.AppList.Data.Config.NodeGroupConf.NodeGroupList {
		for _, info := range ng.AddressInfo {
			addr := strings.TrimSpace(info.Address)
			if addr == "" {
				continue
			}
			addr = strings.ReplaceAll(addr, "{{sdpcHost}}", controllerHost)
			if !strings.Contains(addr, ":") {
				addr += ":441"
			}
			if !seen[addr] {
				seen[addr] = true
				res.Gateways = append(res.Gateways, addr)
			}
		}
	}

	for _, opt := range []struct{ First, Second string }{
		{cr.SDPPolicy.Data.ClientOption.DNSOption.FirstDNS, cr.SDPPolicy.Data.ClientOption.DNSOption.SecondDNS},
		{cr.SDPPolicy.Data.ClientOption.DNSOptionV2.FirstDNS, cr.SDPPolicy.Data.ClientOption.DNSOptionV2.SecondDNS},
	} {
		for _, server := range []string{opt.First, opt.Second} {
			if server != "" && net.ParseIP(server) != nil {
				res.DNS = append(res.DNS, server)
			}
		}
	}
	return res
}

// parsePortRange parses addressList port specs: "443", "1-65535", "" / "all".
func parsePortRange(s string) PortRange {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return allPorts()
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		min, err1 := strconv.Atoi(strings.TrimSpace(lo))
		max, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 == nil && err2 == nil {
			return PortRange{min, max}
		}
		return allPorts()
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return allPorts()
	}
	return PortRange{port, port}
}

func (c *Client) controllerHost() string {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isDottedIPv4(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}
