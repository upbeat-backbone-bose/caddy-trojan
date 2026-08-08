package app

import "testing"

func TestValidateProxyTarget(t *testing.T) {
	t.Parallel()

	valid := []string{
		"example.com:443",
		"1.2.3.4:80",
		"[::1]:8080",
		"a.b-c.example.com:9999",
		"xn--bcher-kva.example:443",
	}
	for _, addr := range valid {
		if err := validateProxyTarget(addr); err != nil {
			t.Errorf("validateProxyTarget(%q) = %v, want nil", addr, err)
		}
	}

	invalid := []string{
		"evil.com\r\nX-Injected: 1:80",
		"evil.com\nX-Injected: 1:80",
		"evil.com:80\x00",
		"sp ace.com:80",
		"tab\t.com:80",
	}
	for _, addr := range invalid {
		if err := validateProxyTarget(addr); err == nil {
			t.Errorf("validateProxyTarget(%q) = nil, want error", addr)
		}
	}
}
