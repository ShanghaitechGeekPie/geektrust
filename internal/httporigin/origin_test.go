package httporigin

import (
	"net/url"
	"testing"
)

func TestSame(t *testing.T) {
	for _, test := range []struct {
		name, first, second string
		want                bool
	}{
		{"https default port", "https://example.edu.cn/login", "https://example.edu.cn:443/result", true},
		{"https reverse", "https://example.edu.cn:443", "https://example.edu.cn", true},
		{"host case", "https://EXAMPLE.edu.cn", "https://example.edu.cn:443", true},
		{"http default port", "http://example.edu.cn", "http://example.edu.cn:80", true},
		{"same custom port", "https://example.edu.cn:8443", "https://example.edu.cn:8443/result", true},
		{"ipv6 default port", "https://[::1]", "https://[::1]:443", true},
		{"different port", "https://example.edu.cn", "https://example.edu.cn:8443", false},
		{"different host", "https://example.edu.cn", "https://other.edu.cn:443", false},
		{"downgrade", "https://example.edu.cn", "http://example.edu.cn:443", false},
		{"userinfo", "https://example.edu.cn", "https://user@example.edu.cn", false},
		{"unsupported scheme", "file://example.edu.cn", "file://example.edu.cn", false},
		{"missing host", "https:/login", "https:/login", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, err := url.Parse(test.first)
			if err != nil {
				t.Fatal(err)
			}
			b, err := url.Parse(test.second)
			if err != nil {
				t.Fatal(err)
			}
			if got := Same(a, b); got != test.want {
				t.Fatalf("Same = %t, want %t", got, test.want)
			}
		})
	}
	if Same(nil, &url.URL{}) || Same(&url.URL{}, nil) {
		t.Fatal("missing URL accepted")
	}
}
