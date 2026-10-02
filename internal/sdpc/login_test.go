package sdpc

import (
	"context"
	"errors"
	"fmt"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthCheckRejectsUnknownSteps(t *testing.T) {
	for _, tc := range []struct {
		body             string
		sms, unsupported bool
	}{
		{`{}`, false, false},
		{`{"nextService":"auth/sms"}`, true, false},
		{`{"nextServiceList":[{"authType":"auth/sms"}]}`, true, false},
		{`{"nextService":"auth/captcha","nextServiceList":[{"authType":"auth/sms"}]}`, false, true},
		{`{"nextServiceList":[{"authType":"auth/captcha"}]}`, false, true},
	} {
		t.Run(tc.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"code":0,"data":%s}`, tc.body) }))
			defer server.Close()
			client := NewClient(server.URL, "Mac", "device", server.Client())
			sms, err := client.AuthCheck(context.Background())
			if sms != tc.sms || errors.Is(err, auth.ErrUnsupported) != tc.unsupported || (!tc.unsupported && err != nil) {
				t.Fatalf("sms=%v err=%v", sms, err)
			}
		})
	}
}
