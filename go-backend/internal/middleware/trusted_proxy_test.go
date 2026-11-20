// Unit test keamanan: header X-Real-IP / X-Forwarded-For hanya boleh dipercaya
// kalau koneksi datang dari reverse proxy terdaftar.
//
// Tanpa batasan ini, siapa pun yang bisa menyentuh port aplikasi langsung cukup
// mengirim X-Real-IP acak untuk mendapat bucket rate limit baru tanpa batas —
// artinya proteksi brute force di /api/auth/login bisa dilewati sepenuhnya.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newIPContext(t *testing.T, remoteAddr, realIP, forwardedFor string) *gin.Context {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	req.RemoteAddr = remoteAddr
	if realIP != "" {
		req.Header.Set("X-Real-IP", realIP)
	}
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	return c
}

func TestClientIPTanpaProxyTerpercaya(t *testing.T) {
	// Hanya loopback yang dipercaya (default produksi).
	SetTrustedProxies([]string{"127.0.0.1", "::1"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	c := newIPContext(t, "203.0.113.9:5555", "1.2.3.4", "5.6.7.8")

	if got := clientIP(c); got != "203.0.113.9" {
		t.Fatalf("header dari klien non-proxy harus diabaikan, dapat %q", got)
	}
}

func TestClientIPDariProxyTerpercaya(t *testing.T) {
	SetTrustedProxies([]string{"127.0.0.1", "::1"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	c := newIPContext(t, "127.0.0.1:5555", "1.2.3.4", "")

	if got := clientIP(c); got != "1.2.3.4" {
		t.Fatalf("X-Real-IP dari proxy terpercaya harus dipakai, dapat %q", got)
	}
}

func TestClientIPDariProxyCIDR(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	c := newIPContext(t, "10.20.30.40:5555", "198.51.100.7", "")

	if got := clientIP(c); got != "198.51.100.7" {
		t.Fatalf("proxy dalam CIDR terdaftar harus dipercaya, dapat %q", got)
	}
}

func TestClientIPHeaderSampahDariProxy(t *testing.T) {
	SetTrustedProxies([]string{"127.0.0.1"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	c := newIPContext(t, "127.0.0.1:5555", "bukan-ip", "")

	if got := clientIP(c); got != "127.0.0.1" {
		t.Fatalf("X-Real-IP tidak valid harus diabaikan, dapat %q", got)
	}
}

func TestClientIPDaftarKosongTidakMempercayaiApaPun(t *testing.T) {
	SetTrustedProxies(nil)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	c := newIPContext(t, "127.0.0.1:5555", "1.2.3.4", "")

	if got := clientIP(c); got != "127.0.0.1" {
		t.Fatalf("tanpa proxy terdaftar, loopback pun tidak boleh dianggap proxy, dapat %q", got)
	}
}
