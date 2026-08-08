package rawconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestRewindConnTLS verifies that plaintext already read from a *tls.Conn can
// be replayed through RewindConn on the current Go release.
func TestRewindConnTLS(t *testing.T) {
	cert := testCertificate(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientTLS := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	serverTLS := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})

	errCh := make(chan error, 1)
	go func() { errCh <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	msg := []byte("hello world")
	go func() {
		if _, err := clientTLS.Write(msg); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()

	// Read part of the plaintext, then rewind and expect the full message.
	first := make([]byte, len("hello"))
	if _, err := io.ReadFull(serverTLS, first); err != nil {
		t.Fatalf("first read: %v", err)
	}

	rc := RewindConn(serverTLS, first)
	all := make([]byte, len(msg))
	if _, err := io.ReadFull(rc, all); err != nil {
		t.Fatalf("read after rewind: %v", err)
	}
	if string(all) != string(msg) {
		t.Fatalf("after rewind got %q, want %q", all, msg)
	}
}

// TestRewindConnTLSState verifies that the wrapper returned by RewindConn
// forwards the TLS connection state to caddy/net/http instead of hiding it.
func TestRewindConnTLSState(t *testing.T) {
	cert := testCertificate(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientTLS := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	serverTLS := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})

	errCh := make(chan error, 1)
	go func() { errCh <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	rc := RewindConn(serverTLS, nil)

	// The wrapper must expose the exported connectionStater method so caddy's
	// http2listener/ConnContext path can recover the TLS state.
	stater, ok := rc.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		t.Fatal("RewindConn result does not implement ConnectionState")
	}
	if got := stater.ConnectionState(); got.Version == 0 {
		t.Errorf("ConnectionState = %+v, want valid TLS version", got)
	}
}

// TestRewindConnPlainState verifies that rewinding a non-TLS connection stays
// safe: ConnectionState returns an empty, not-valid state instead of panicking.
func TestRewindConnPlainState(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rc := RewindConn(c1, []byte("x"))
	stater, ok := rc.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		t.Fatal("RewindConn result does not implement ConnectionState")
	}
	if got := stater.ConnectionState(); got.Version != 0 {
		t.Errorf("plain conn ConnectionState = %+v, want empty state", got)
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
