package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestShadowsocksProvisionInitializesCipherWithPreProxy is a regression test
// for a startup-crash bug: Provision's pre_proxy branch used to return
// before the cipher was initialized, so the first Dial/ListenPacket on a
// ShadowsocksProxy with a pre_proxy chain would panic with a nil
// core.Cipher, taking down the whole caddy process. After the fix, the
// cipher is initialized regardless of which branch is taken.
func TestShadowsocksProvisionInitializesCipherWithPreProxy(t *testing.T) {
	t.Parallel()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	p := &ShadowsocksProxy{
		Method:   "aes-256-gcm",
		Password: "testpassword123",
		// Inline pre_proxy pointing at NoProxy (registered as
		// "trojan.proxy.none" via app/proxy.go's init()).
		ProxyRaw: json.RawMessage(`{"proxy":"none"}`),
	}
	if err := p.Provision(ctx); err != nil {
		t.Fatalf("Provision error: %v", err)
	}
	if p.cipher == nil {
		t.Fatal("p.cipher is nil after Provision with pre_proxy \u2014 the cipher must be initialized regardless of pre_proxy presence")
	}
}

// TestShadowsocksProvisionPropagatesLoadModuleError is a regression test for
// swallowed LoadModule errors: Provision used to return nil on a bad
// pre_proxy config, silently starting up with a half-configured proxy that
// would later crash on first dial. After the fix, LoadModule errors are
// propagated so misconfiguration is caught at startup.
func TestShadowsocksProvisionPropagatesLoadModuleError(t *testing.T) {
	t.Parallel()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	p := &ShadowsocksProxy{
		Method:   "aes-256-gcm",
		Password: "testpassword123",
		// "this-module-does-not-exist" does not match any registered
		// trojan.proxy.* module, so LoadModule must return an error.
		ProxyRaw: json.RawMessage(`{"proxy":{"this-module-does-not-exist":{}}}`),
	}
	if err := p.Provision(ctx); err == nil {
		t.Fatal("Provision with unknown pre_proxy module = nil, want error")
	}
}