package middleware

import (
	"net"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// Proxy terdaftar — satu-satunya sumber yang boleh mengisi header IP klien.
// Daftar ini diisi sekali saat startup lewat SetTrustedProxies.
var (
	trustedProxyMu sync.RWMutex
	trustedNets    []*net.IPNet
	trustedIPs     []net.IP
)

// SetTrustedProxies menetapkan IP/CIDR reverse proxy yang dipercaya.
// Default aman: hanya loopback, jadi aplikasi yang diakses langsung dari luar
// mengabaikan header X-Real-IP / X-Forwarded-For.
func SetTrustedProxies(list []string) {
	trustedProxyMu.Lock()
	defer trustedProxyMu.Unlock()

	trustedNets = nil
	trustedIPs = nil

	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil {
				trustedNets = append(trustedNets, ipnet)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			trustedIPs = append(trustedIPs, ip)
		}
	}
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}

	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()

	for _, candidate := range trustedIPs {
		if candidate.Equal(ip) {
			return true
		}
	}
	for _, ipnet := range trustedNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP mengembalikan IP klien untuk keperluan rate limit.
//
// Header X-Real-IP / X-Forwarded-For hanya dipakai kalau koneksi datang dari
// proxy terdaftar. Tanpa pemeriksaan ini, siapa pun yang bisa menyentuh port
// aplikasi langsung cukup mengirim header itu untuk mendapat bucket rate limit
// baru tanpa batas — termasuk mem-bypass proteksi brute force di /api/auth.
func clientIP(c *gin.Context) string {
	remote := c.RemoteIP()

	if parsed := net.ParseIP(remote); parsed != nil && isTrustedProxy(parsed) {
		// X-Real-IP ditulis ulang oleh nginx ($remote_addr) dan berisi satu IP.
		if realIP := net.ParseIP(strings.TrimSpace(c.GetHeader("X-Real-IP"))); realIP != nil {
			return realIP.String()
		}
		// ClientIP() sudah menelusuri X-Forwarded-For dan hanya percaya pada
		// proxy yang terdaftar di gin (diset lewat router.SetTrustedProxies).
		return c.ClientIP()
	}

	return remote
}
