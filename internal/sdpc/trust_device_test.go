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
		if got := r.URL.Query().Get("status"); got != "trust" {
			t.Errorf("status = %q, want trust", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "OK",
			"data": map[string]any{
				"data": []map[string]any{
					{"id": "dev-1", "deviceName": "Test-Mac", "deviceType": "browser",
						"os": "macOS", "osVersion": "15.5", "lastLoginIp": "192.0.2.2",
						"lastLoginAddress": "test-zone", "networkZoneList": []string{"test-network"}, "onlineStatus": true},
					{"id": "dev-2", "deviceName": "Test-Windows", "deviceType": "windows", "onlineStatus": false},
				},
				"selfId":             "dev-1",
				"currentTrustStatus": 1,
				"trustDeviceConfig":  map[string]any{"enable": true},
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
	if list.SelfID != "dev-1" || list.CurrentTrustStatus != 1 || !list.Config.Enable {
		t.Errorf("list = %+v", list)
	}
	d := list.Devices[0]
	if d.ID != "dev-1" || d.DeviceType != "browser" || d.OS != "macOS" || d.LastLoginIP == "" {
		t.Errorf("device[0] = %+v", d)
	}
	if !d.OnlineStatus {
		t.Errorf("device[0].onlineStatus = false, want true")
	}
}

func TestQueryUntrustedDevice(t *testing.T) {
	c := newTrustTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("status"); got != "untrust" {
			t.Errorf("status = %q, want untrust", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "OK",
			"data": map[string]any{
				"data": []map[string]any{{"id": "dev-9", "deviceName": "Old PC"}},
			},
		})
	})

	devs, err := c.QueryUntrustedDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].ID != "dev-9" {
		t.Errorf("devices = %+v", devs)
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
			"code":    75500000,
			"message": "当前未安装客户端或使用纯web模式登录，无法添加授信终端",
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
	if apiErr.Code != 75500000 {
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
