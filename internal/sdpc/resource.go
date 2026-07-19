package sdpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// AppEndpoint is a resolved tunnel target: the internal IP plus the app that
// authorizes it.
type AppEndpoint struct {
	IP    string
	AppID string
}

// Resource is the parsed clientResource payload (TECHNICAL.md §4).
type Resource struct {
	// DomainMap maps a domain to its first internal IP and owning app.
	DomainMap map[string]AppEndpoint
	// IPApps maps an internal IP to its owning app (for direct-IP targets).
	IPApps map[string]string
	// Gateways are the node group access addresses (host:port, default 441).
	Gateways []string
	// DNS are controller-pushed resolver addresses, if any.
	DNS []string
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

// ClientResource fetches the app/resource list via the unsigned browser path
// (TECHNICAL.md §4.1) and derives the domain map and gateway lines.
func (c *Client) ClientResource(ctx context.Context) (*Resource, error) {
	rawJSON, err := c.RawClientResource(ctx)
	if err != nil {
		return nil, err
	}
	var raw clientResource
	if err := json.Unmarshal(rawJSON, &raw); err != nil {
		return nil, fmt.Errorf("clientResource: decode: %w", err)
	}
	return c.parseResource(&raw), nil
}

// RawClientResource returns the unparsed data payload of clientResource,
// useful for diagnostics.
func (c *Client) RawClientResource(ctx context.Context) (json.RawMessage, error) {
	body := map[string]any{
		"resourceType": map[string]any{
			"sdpPolicy":       map[string]any{},
			"appList":         map[string]any{},
			"favoriteAppList": map[string]any{},
			"featureCenter":   map[string]any{},
			"uemSpace":        map[string]any{"params": map[string]string{"action": "login"}},
		},
	}
	var data json.RawMessage
	if err := c.doJSON(ctx, "POST", "/controller/v1/user/clientResource", url.Values{}, body, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// parseResource builds the domain→internal-IP map (TECHNICAL.md §4.2) and the
// gateway line list (§4.3), following the reference build_domain_map rules:
// strip "@suffix"; pure dotted-numeric hosts are internal IPs; hosts with
// "*", "-" or "/" are ranges and never mapped; each domain maps to the first
// internal IP of the same app.
func (c *Client) parseResource(cr *clientResource) *Resource {
	res := &Resource{
		DomainMap: make(map[string]AppEndpoint),
		IPApps:    make(map[string]string),
	}
	for _, group := range cr.AppList.Data.AppInfo {
		for _, app := range group.Apps {
			var ips, domains []string
			for _, entry := range app.AddressList {
				host := entry.Host
				if i := strings.IndexByte(host, '@'); i >= 0 {
					host = host[i+1:]
				}
				switch {
				case host == "":
				case isDottedIPv4(host):
					ips = append(ips, host)
					if _, ok := res.IPApps[host]; !ok {
						res.IPApps[host] = app.ID
					}
				case !strings.ContainsAny(host, "*-/"):
					domains = append(domains, host)
				}
			}
			if len(ips) > 0 {
				for _, domain := range domains {
					// First-wins: an address shared by several apps (e.g.
					// 10.15.45.163 belongs to both 电子资源 and a security
					// agent app) must keep the first declaring app, or the
					// gateway's per-conn address check rejects the dial
					// (code 10000005).
					if _, ok := res.DomainMap[domain]; !ok {
						res.DomainMap[domain] = AppEndpoint{IP: ips[0], AppID: app.ID}
					}
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

func (c *Client) controllerHost() string {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isDottedIPv4 reports whether s is a plain dotted-quad (the reference uses
// host.replace(".", "").isdigit()).
func isDottedIPv4(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return net.ParseIP(s) != nil && net.ParseIP(s).To4() != nil && !strings.Contains(s, ":")
}
