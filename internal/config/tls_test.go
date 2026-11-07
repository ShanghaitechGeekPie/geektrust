package config

import "testing"

func TestGatewayInsecureSkipVerify(t *testing.T) {
	for _, format := range []struct{ name, base string }{
		{"legacy", "keystore = 'credential'\n"},
		{"v2", "config_version = 2\n[auth.passkey]\nkeystore = 'credential'\n[storage]\ndirectory = './private'\n[tls.gateway]\n"},
	} {
		for _, tc := range []struct {
			name, setting string
			want          bool
		}{
			{"default", "", false},
			{"disabled", "insecure_skip_verify = false\n", false},
			{"enabled", "insecure_skip_verify = true\n", true},
		} {
			t.Run(format.name+"/"+tc.name, func(t *testing.T) {
				cfg, err := Load(writeConfig(t, format.base+tc.setting))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.InsecureSkipVerify != tc.want || len(cfg.UnknownFields) != 0 {
					t.Fatalf("insecure_skip_verify=%t, unknown fields=%v", cfg.InsecureSkipVerify, cfg.UnknownFields)
				}
			})
		}
	}
}
