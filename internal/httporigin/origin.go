// Package httporigin compares HTTP origins without treating a default port as a different origin.
package httporigin

import (
	"net/url"
	"strings"
)

func Same(a, b *url.URL) bool {
	if a == nil || b == nil || a.User != nil || b.User != nil || a.Hostname() == "" || b.Hostname() == "" {
		return false
	}
	scheme := strings.ToLower(a.Scheme)
	if (scheme != "https" && scheme != "http") || scheme != strings.ToLower(b.Scheme) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}
