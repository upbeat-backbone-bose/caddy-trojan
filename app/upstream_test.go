package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

// TestMemoryUpstreamValidateConsumeDelete exercises the key lifecycle of
// MemoryUpstream: Add → Validate hit/miss → Consume → Delete → Validate miss.
func TestMemoryUpstreamValidateConsumeDelete(t *testing.T) {
	t.Parallel()

	u := &MemoryUpstream{}
	u.mm = make(map[string]Traffic)

	if err := u.Add("pass1234"); err != nil {
		t.Fatalf("Add error: %v", err)
	}

	var key string
	u.Range(func(k string, _, _ int64) {
		key = k
	})
	if key == "" {
		t.Fatal("no key stored after Add")
	}

	if !u.Validate(key) {
		t.Error("Validate(valid key) = false, want true")
	}
	if u.Validate("00000000000000000000000000000000000000000000000000000000") {
		t.Error("Validate(wrong key) = true, want false")
	}

	if err := u.Consume(key, 100, 200); err != nil {
		t.Fatalf("Consume error: %v", err)
	}
	u.Range(func(k string, up, down int64) {
		if k == key && (up != 100 || down != 200) {
			t.Errorf("Consume recorded up=%d down=%d, want 100/200", up, down)
		}
	})

	if err := u.Delete("pass1234"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if u.Validate(key) {
		t.Error("Validate(key after Delete) = true, want false")
	}
}

// TestMemoryUpstreamConsumeDeepCopiesKey is a regression test for a zero-copy
// aliasing bug: callers (handler/listener) hand Consume a string produced by
// x.ByteSliceToString, which aliases a stack- or heap-owned buffer. If Consume
// uses that string directly as a map key, later mutations to (or GC reuse of)
// the backing buffer silently corrupt the map key. Consume must clone the
// key before storing it.
func TestMemoryUpstreamConsumeDeepCopiesKey(t *testing.T) {
	t.Parallel()

	u := &MemoryUpstream{}
	u.mm = make(map[string]Traffic)

	// Build a heap-allocated backing buffer of HeaderLen bytes; the zero-copy
	// string will alias it.
	buf := make([]byte, trojan.HeaderLen)
	for i := range buf {
		buf[i] = 'x'
	}
	want := strings.Repeat("x", trojan.HeaderLen)

	zeroCopy := x.ByteSliceToString(buf)
	if zeroCopy != want {
		t.Fatalf("setup: zeroCopy=%q, want %q", zeroCopy, want)
	}

	// Consume stores the key (under lock) and the persistent goroutine path is
	// skipped because u.up is nil.
	if err := u.Consume(zeroCopy, 1, 2); err != nil {
		t.Fatalf("Consume error: %v", err)
	}

	// Mutate the backing buffer. With a proper deep copy, the map key must be
	// unaffected. Without strings.Clone, the key would now read 'y's.
	for i := range buf {
		buf[i] = 'y'
	}

	var got string
	u.Range(func(k string, _, _ int64) {
		got = k
	})
	if got != want {
		t.Errorf("map key was aliased to caller's buffer: got %q, want %q", got, want)
	}
}

// TestMemoryUpstreamSendTaskSurvivesClosedChannel is a regression test for a
// shutdown race: Cleanup closes u.ch while in-flight Add/Delete/Consume calls
// may still try to send on it. Without sendTask's recover, the send on a
// closed channel would panic and crash the whole process. With it, the panic
// is swallowed and the call returns nil.
func TestMemoryUpstreamSendTaskSurvivesClosedChannel(t *testing.T) {
	t.Parallel()

	u := &MemoryUpstream{}
	u.mm = make(map[string]Traffic)
	// u.up must be non-nil so Add/Delete/Consume actually reach sendTask;
	// with u.up == nil they early-return before the send.
	u.up = noopUpstream{}
	u.ch = make(chan Task, 16)

	// Cleanup closes u.ch.
	if err := u.Cleanup(); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	// None of these calls must panic, even though u.ch is closed.
	if err := u.Add("pass1234"); err != nil {
		t.Errorf("Add after Cleanup = %v, want nil", err)
	}
	if err := u.Delete("pass1234"); err != nil {
		t.Errorf("Delete after Cleanup = %v, want nil", err)
	}
	if err := u.Consume("k", 1, 2); err != nil {
		t.Errorf("Consume after Cleanup = %v, want nil", err)
	}
}

// noopUpstream satisfies app.Upstream without doing anything; used by tests
// that need u.up to be non-nil so Add/Delete/Consume reach sendTask.
type noopUpstream struct{}

func (noopUpstream) Add(string) error                   { return nil }
func (noopUpstream) Delete(string) error                { return nil }
func (noopUpstream) Range(func(string, int64, int64))   {}
func (noopUpstream) Validate(string) bool               { return true }
func (noopUpstream) Consume(string, int64, int64) error { return nil }

// TestMemoryUpstreamValidateAppliesDelay verifies the constant-time delay on
// MemoryUpstream.Validate: both hit and miss paths must take ≥validateDelay
// (250ms). Without this, an attacker can distinguish valid from invalid
// passwords by timing and use the channel for online guessing.
func TestMemoryUpstreamValidateAppliesDelay(t *testing.T) {
	t.Parallel()

	u := &MemoryUpstream{}
	u.mm = make(map[string]Traffic)
	if err := u.Add("pass1234"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	var key string
	u.Range(func(k string, _, _ int64) { key = k })

	miss := strings.Repeat("0", trojan.HeaderLen)

	for _, tc := range []struct {
		name string
		k    string
	}{
		{"hit", key},
		{"miss", miss},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			u.Validate(tc.k)
			elapsed := time.Since(start)
			if elapsed < validateDelay {
				t.Errorf("Validate(%s) took %v, want ≥%v (constant-time)", tc.name, elapsed, validateDelay)
			}
		})
	}
}

// TestCaddyUpstreamValidateAppliesDelay verifies the same constant-time delay
// on CaddyUpstream.Validate. CaddyUpstream stores traffic in certmagic.Storage
// rather than an in-memory map, but the same timing-side-channel concern
// applies; the fix is identical.
func TestCaddyUpstreamValidateAppliesDelay(t *testing.T) {
	t.Parallel()

	store := newMemStorage()
	u := &CaddyUpstream{
		prefix:  "trojan/",
		storage: store,
	}

	const pw = "pass1234"
	if err := u.Add(pw); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	var key string
	u.Range(func(k string, _, _ int64) { key = k })

	miss := strings.Repeat("0", trojan.HeaderLen)

	for _, tc := range []struct {
		name string
		k    string
	}{
		{"hit", key},
		{"miss", miss},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			u.Validate(tc.k)
			elapsed := time.Since(start)
			if elapsed < validateDelay {
				t.Errorf("Validate(%s) took %v, want ≥%v (constant-time)", tc.name, elapsed, validateDelay)
			}
		})
	}
}

// memStorage is a minimal in-memory certmagic.Storage used only by tests.
// It implements the subset of the interface CaddyUpstream touches: Store,
// Load, Delete, Exists, List, Stat, plus Lock/Unlock from Locker.
type memStorage struct {
	data map[string][]byte
}

func newMemStorage() *memStorage {
	return &memStorage{data: make(map[string][]byte)}
}

func (m *memStorage) Store(_ context.Context, key string, value []byte) error {
	m.data[key] = value
	return nil
}

func (m *memStorage) Load(_ context.Context, key string) ([]byte, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (m *memStorage) Delete(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *memStorage) Exists(_ context.Context, key string) bool {
	_, ok := m.data[key]
	return ok
}

func (m *memStorage) List(_ context.Context, prefix string, _ bool) ([]string, error) {
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	v, ok := m.data[key]
	if !ok {
		return certmagic.KeyInfo{}, nil
	}
	return certmagic.KeyInfo{Key: key, Size: int64(len(v))}, nil
}

func (m *memStorage) Lock(_ context.Context, _ string) error   { return nil }
func (m *memStorage) Unlock(_ context.Context, _ string) error { return nil }
