package sdpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTrustTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-csrf-token") == "" {
			w.WriteHeader(403)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	hc := &http.Client{}
	c := NewClient(srv.URL, "Mac", "84B5B45FE73EC0036C3E97717308447F", hc)
	c.csrf = "test-csrf"
	return c
}

func TestQueryTrustDevice(t *testing.T) {
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/queryDevice" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Query().Get("clientType") != ClientTypeBrowser {
			t.Errorf("clientType = %s", r.URL.Query().Get("clientType"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "OK",
			"data": map[string]any{
				"deviceList": []map[string]any{
					{"id": "dev-1", "deviceName": "MacBook", "isCurrent": true},
					{"id": "dev-2", "deviceName": "iPhone", "isCurrent": false},
				},
				"maxCount":      5,
				"currentCount":  2,
				"deviceTrusted": true,
			},
		})
	})

	list, err := c.QueryTrustDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Devices) != 2 {
		t.Fatalf("device count = %d", len(list.Devices))
	}
	if list.MaxCount != 5 || list.CurrentCount != 2 || !list.DeviceTrusted {
		t.Errorf("list = %+v", list)
	}
	if list.Devices[0].ID != "dev-1" || !list.Devices[0].Current {
		t.Errorf("device[0] = %+v", list.Devices[0])
	}
}

func TestTrustDeviceBind(t *testing.T) {
	var gotBody string
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/trustDevice" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json;charset=utf-8" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		if r.URL.Query().Get("platform") != "Mac" {
			t.Errorf("platform = %s", r.URL.Query().Get("platform"))
		}
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "OK", "data": map[string]any{}})
	})

	if err := c.TrustDevice(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(gotBody) != "{}" {
		t.Errorf("body = %q", gotBody)
	}
}

func TestTrustDeviceBindError(t *testing.T) {
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"code":    75500311,
			"message": "ADD_TRUST_DEVICE_UPPER_LIMIT",
			"data":    nil,
		})
	})

	err := c.TrustDevice(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T", err)
	}
	if apiErr.Code != 75500311 {
		t.Errorf("code = %d", apiErr.Code)
	}
}

func TestUntrustDevice(t *testing.T) {
	var gotBody string
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/untrustDevice" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "OK"})
	})

	if err := c.UntrustDevice(context.Background(), []string{"dev-1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, "dev-1") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestUntrustDeviceEmpty(t *testing.T) {
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called")
	})
	if err := c.UntrustDevice(context.Background(), nil); err == nil {
		t.Fatal("expected error for empty idList")
	}
}

func TestLogoutDevice(t *testing.T) {
	var gotBody string
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/logoutDevice" {
			t.Errorf("path = %s", r.URL.Path)
		}
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "OK"})
	})

	if err := c.LogoutDevice(context.Background(), "dev-1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, "dev-1") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestLogoutDeviceEmpty(t *testing.T) {
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called")
	})
	if err := c.LogoutDevice(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}
