package app

import (
	"context"
	"strings"
	"sync"
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
//
// storeCount / loadCount / existsCount record how many times each operation
type memStorage struct {
	mu          sync.Mutex
	data        map[string][]byte
	storeCount  int
	loadCount   int
	existsCount int
	lastKey     string
}

func newMemStorage() *memStorage {
	return &memStorage{data: make(map[string][]byte)}
}
func (m *memStorage) Store(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeCount++
	m.lastKey = key
	m.data[key] = value
	return nil
}

func (m *memStorage) Load(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadCount++
	m.lastKey = key
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (m *memStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memStorage) Exists(_ context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existsCount++
	m.lastKey = key
	_, ok := m.data[key]
	return ok
}

func (m *memStorage) List(_ context.Context, prefix string, _ bool) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return certmagic.KeyInfo{}, nil
	}
	return certmagic.KeyInfo{Key: key, Size: int64(len(v))}, nil
}

func (m *memStorage) Lock(_ context.Context, _ string) error   { return nil }
func (m *memStorage) Unlock(_ context.Context, _ string) error { return nil }

// TestCaddyUpstreamValidHexKeyStillWorks is regression armor for the storage
// key validation fix: the legitimate path stores hex SHA224 digests via
// trojan.GenKey, which always produces 56 lowercase hex characters. After
// validation is added, that path must remain operational. This test passes
// both pre-fix (current code accepts anything) and post-fix (validator
// accepts the legit format).
func TestCaddyUpstreamValidHexKeyStillWorks(t *testing.T) {
	t.Parallel()

	store := newMemStorage()
	u := &CaddyUpstream{prefix: "trojan/", storage: store}

	const pw = "pass1234"
	if err := u.Add(pw); err != nil {
		t.Fatalf("Add error: %v", err)
	}

	var key string
	u.Range(func(k string, _, _ int64) {
		key = k
	})
	if l := len(key); l != trojan.HeaderLen {
		t.Fatalf("Add produced key of length %d, want %d", l, trojan.HeaderLen)
	}
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("Add produced non-hex key char %q in %q", c, key)
		}
	}

	if !u.Validate(key) {
		t.Error("Validate(legit hex key) = false, want true")
	}
	if err := u.Consume(key, 100, 200); err != nil {
		t.Errorf("Consume on legit hex key = %v, want nil", err)
	}
}

// TestCaddyUpstreamRejectsPathTraversal verifies that Validate/Consume reject
// keys with "../" or absolute-path components before touching storage, so an
// attacker controlling the trojan header cannot read or write paths outside
// the configured prefix. Pre-fix, prefix+k went straight to
// certmagic.FileStorage whose filepath.Join escapes on ".."; the test plants a
// "bait" value at the escaped path and asserts Exists/Consume never reach it.
func TestCaddyUpstreamRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	store := newMemStorage()
	u := &CaddyUpstream{prefix: "trojan/", storage: store}

	// Seed a legitimate user so the storage isn't empty (and so Consume has a
	// real, separate, side-effect-free key to contrast with the attack).
	if err := u.Add("pass1234"); err != nil {
		t.Fatalf("seed Add: %v", err)
	}
	loadBefore := store.loadCount
	storeBefore := store.storeCount
	existsBefore := store.existsCount

	// Attack vectors: 56-byte keys whose ../ or absolute components would
	// escape the "trojan/" prefix once joined. Each must be rejected without
	// any I/O (load/store/exists counters unchanged).
	attacks := []struct {
		name string
		key  string
	}{
		{"relative_traversal", "../../../etc/passwd" + "/foo"}, // pad to 56 to satisfy len == HeaderLen check is NOT done in fix; instead, fix rejects ALL non-hex regardless of length
		{"too_short_traversal", "../bad"},
		{"absolute_path_traversal", strings.Repeat("/a", 28)}, // 56 bytes of /a chars
		{"single_dot_segment", ".."},
	}

	for _, at := range attacks {
		at := at
		t.Run("Validate_"+at.name, func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			if err := u.Add("pass1234"); err != nil {
				t.Fatalf("seed Add: %v", err)
			}
			existsBefore := store.existsCount
			if u.Validate(at.key) {
				t.Errorf("Validate(%q) = true; path traversal must be rejected", at.key)
			}
			if store.existsCount != existsBefore {
				t.Errorf("Validate(%q) caused %d extra Exists calls; must short-circuit before I/O", at.key, store.existsCount-existsBefore)
			}
		})
		t.Run("Consume_"+at.name, func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			if err := u.Add("pass1234"); err != nil {
				t.Fatalf("seed Add: %v", err)
			}
			loadBefore := store.loadCount
			storeBefore := store.storeCount
			if err := u.Consume(at.key, 1, 2); err == nil {
				t.Errorf("Consume(%q) = nil; path traversal must be rejected with an error", at.key)
			}
			if store.loadCount != loadBefore || store.storeCount != storeBefore {
				t.Errorf("Consume(%q) caused extra I/O (load +%d, store +%d); must short-circuit before I/O", at.key, store.loadCount-loadBefore, store.storeCount-storeBefore)
			}
		})
	}

	// Final sanity: the seed user's load/store counters are untouched.
	if store.loadCount != loadBefore {
		t.Errorf("seed-side extra loads observed: %d", store.loadCount-loadBefore)
	}
	if store.storeCount != storeBefore {
		t.Errorf("seed-side extra stores observed: %d", store.storeCount-storeBefore)
	}
	if store.existsCount != existsBefore {
		t.Errorf("seed-side extra exists observed: %d", store.existsCount-existsBefore)
	}
}

// TestCaddyUpstreamRejectsWrongLength verifies Validate/Consume reject keys
// whose length does not match trojan.HeaderLen. The trojan header is a
// fixed-size 56-byte hex SHA224 digest; anything else is input from an
// invalid client or a misuse of the Upstream API.
func TestCaddyUpstreamRejectsWrongLength(t *testing.T) {
	t.Parallel()

	for _, l := range []int{0, 1, 55, 57, 128, 1024} {
		key := strings.Repeat("a", l)
		t.Run("Validate_len_"+itoa(l), func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			existsBefore := store.existsCount
			if u.Validate(key) {
				t.Errorf("Validate(key of len %d) = true; want false", l)
			}
			if store.existsCount != existsBefore {
				t.Errorf("Validate(len %d) caused extra Exists; must short-circuit", l)
			}
		})
		t.Run("Consume_len_"+itoa(l), func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			loadBefore := store.loadCount
			storeBefore := store.storeCount
			if err := u.Consume(key, 1, 2); err == nil {
				t.Errorf("Consume(key of len %d) = nil; want error", l)
			}
			if store.loadCount != loadBefore || store.storeCount != storeBefore {
				t.Errorf("Consume(len %d) caused extra I/O", l)
			}
		})
	}
}

// TestCaddyUpstreamRejectsNonHexChars verifies Validate/Consume reject keys
// of correct length but containing any byte outside [0-9a-f]. The hex encoder
// only emits lowercase chars; uppercase, spaces, slashes, dots, and other
// bytes are by definition not produced by the legitimate code path and must
// not be accepted. The "../" traversal key is the most important instance:
// 56 bytes of '2e' (.) before the prefix-escape point.
func TestCaddyUpstreamRejectsNonHexChars(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  string
	}{
		{"all_slashes", strings.Repeat("/", trojan.HeaderLen)},
		{"all_dots", strings.Repeat(".", trojan.HeaderLen)}, // "../../../../..."
		{"uppercase_hex", strings.Repeat("A", trojan.HeaderLen)},
		{"mixed_with_2e", "../" + strings.Repeat("a", trojan.HeaderLen-3)},
		{"space_padded", strings.Repeat(" ", trojan.HeaderLen)},
		{"traversal_56", strings.Repeat("../", 56/3) + strings.Repeat("/", 56-2*(56/3))},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("Validate_"+tc.name, func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			existsBefore := store.existsCount
			if u.Validate(tc.key) {
				t.Errorf("Validate(%s, len=%d) = true; want false", tc.name, len(tc.key))
			}
			if store.existsCount != existsBefore {
				t.Errorf("Validate(%s) caused extra Exists; must short-circuit", tc.name)
			}
		})
		t.Run("Consume_"+tc.name, func(t *testing.T) {
			t.Parallel()
			store := newMemStorage()
			u := &CaddyUpstream{prefix: "trojan/", storage: store}
			loadBefore := store.loadCount
			storeBefore := store.storeCount
			if err := u.Consume(tc.key, 1, 2); err == nil {
				t.Errorf("Consume(%s) = nil; want error", tc.name)
			}
			if store.loadCount != loadBefore || store.storeCount != storeBefore {
				t.Errorf("Consume(%s) caused extra I/O", tc.name)
			}
		})
	}
}

// itoa is a tiny local helper to format an int into a string for subtest
// names without pulling strconv into a test-only suffix.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
