package config

import (
	"reflect"
	"testing"
)

func TestParseTrustedProxiesDefaultLoopback(t *testing.T) {
	// Kosong = hanya loopback. Jangan sampai fallback ke "trust all",
	// karena itu membuka pemalsuan X-Forwarded-For untuk bypass rate limit.
	for _, in := range []string{"", "   ", " , , "} {
		got := parseTrustedProxies(in)
		want := []string{"127.0.0.1", "::1"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseTrustedProxies(%q) = %v, mau %v", in, got, want)
		}
	}
}

func TestParseTrustedProxiesDaftar(t *testing.T) {
	got := parseTrustedProxies(" 10.0.0.0/8 , 172.16.0.1 ,, 192.168.1.0/24 ")
	want := []string{"10.0.0.0/8", "172.16.0.1", "192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTrustedProxies = %v, mau %v", got, want)
	}
}
