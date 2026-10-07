package idsauth

import "testing"

func TestKeystoreRejectsEmptyQueryMarker(t *testing.T) {
	fields := testKeystoreMap(t)
	fields["base_url"] = "https://ids.shanghaitech.edu.cn?"
	if _, err := ParseKeystore(pythonFormat(t, fields), nil); err == nil {
		t.Fatal("credential origin ending in a query marker was accepted")
	}
}
