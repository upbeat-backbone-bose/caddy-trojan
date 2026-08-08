package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestProxyProvisionPropagatesLoadModuleError is a regression test for
// swallowed LoadModule errors in EnvProxy/SocksProxy/HttpProxy.Provision:
// each used to return nil on a bad pre_proxy config, silently starting up
// with a half-configured proxy that would later crash on first dial. After
// the fix, LoadModule errors are propagated so misconfiguration is caught at
// startup.
func TestProxyProvisionPropagatesLoadModuleError(t *testing.T) {
	t.Parallel()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	bad := json.RawMessage(`{"proxy":"this-module-does-not-exist"}`)

	for _, tc := range []struct {
		name string
		mod  caddy.Module
	}{
		{"EnvProxy", &EnvProxy{ProxyRaw: bad}},
		{"SocksProxy", &SocksProxy{ProxyRaw: bad}},
		{"HttpProxy", &HttpProxy{ProxyRaw: bad}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.mod.(caddy.Provisioner).Provision(ctx); err == nil {
				t.Fatalf("%s.Provision with unknown pre_proxy module = nil, want error", tc.name)
			}
		})
	}
}
