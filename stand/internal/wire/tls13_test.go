package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wire.test"},
		DNSNames:     []string{"wire.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type connection struct {
	client, server []byte
	keys           Keys
	clientHello    *Hello
	serverHello    *Hello
}

func handshakeAndSend(t *testing.T, config *tls.Config, messages [][]byte) connection {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	clientConn := &recordingConn{Conn: clientEnd}
	serverConn := &recordingConn{Conn: serverEnd}

	certificate := selfSignedCertificate(t)
	serverDone := make(chan error, 1)
	go func() {
		conn := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		_, err := io.Copy(io.Discard, conn)
		serverDone <- err
	}()

	var keyLog bytes.Buffer
	config.ServerName = "wire.test"
	config.InsecureSkipVerify = true
	config.KeyLogWriter = &keyLog
	conn := tls.Client(clientConn, config)
	for _, message := range messages {
		if _, err := conn.Write(message); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}
	conn.Close()
	<-serverDone

	result := connection{client: clientConn.bytes(), server: serverConn.bytes(), keys: ParseKeys(keyLog.Bytes())}
	var err error
	if result.clientHello, err = ParseHello(result.client); err != nil {
		t.Fatalf("parse client hello: %v", err)
	}
	if result.serverHello, err = ParseHello(result.server); err != nil {
		t.Fatalf("parse server hello: %v", err)
	}
	return result
}

func TestDecrypt13RecoversTheClientApplicationData(t *testing.T) {
	messages := [][]byte{[]byte("first write"), bytes.Repeat([]byte("x"), 40000), []byte("last write")}
	conn := handshakeAndSend(t, &tls.Config{MinVersion: tls.VersionTLS13}, messages)

	data, err := Decrypt13(conn.client, conn.serverHello.CipherSuites[0],
		conn.keys.Secret(ClientHandshake, conn.clientHello.Random),
		conn.keys.Secret(ClientTraffic, conn.clientHello.Random))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if want := bytes.Join(messages, nil); !bytes.Equal(data, want) {
		t.Fatalf("decrypted %d bytes, want %d", len(data), len(want))
	}
}

func TestDecrypt13FailsWithTheWrongSecret(t *testing.T) {
	conn := handshakeAndSend(t, &tls.Config{MinVersion: tls.VersionTLS13}, [][]byte{[]byte("payload")})

	wrong := bytes.Repeat([]byte{1}, 32)
	if _, err := Decrypt13(conn.client, conn.serverHello.CipherSuites[0], wrong, wrong); err == nil {
		t.Fatal("decryption with a wrong secret reported no error")
	}
}

func TestRecordProtectionCoversEveryTLS13Suite(t *testing.T) {
	for _, suite := range []uint16{tlsAES128GCMSHA256, tlsAES256GCMSHA384, tlsChaCha20Poly1305SHA256} {
		secretLen := 32
		if suite == tlsAES256GCMSHA384 {
			secretLen = 48
		}
		sealer, err := newRecordProtection(suite, bytes.Repeat([]byte{7}, secretLen))
		if err != nil {
			t.Fatalf("suite 0x%04x: %v", suite, err)
		}
		opener, _ := newRecordProtection(suite, bytes.Repeat([]byte{7}, secretLen))

		inner := append([]byte("hello"), contentTypeApplicationData, 0, 0)
		header := []byte{contentTypeApplicationData, 3, 3, 0, byte(len(inner) + sealer.aead.Overhead())}
		sealed := sealer.aead.Seal(nil, xorNonce(sealer.iv, 0), inner, header)

		contentType, plaintext, err := opener.open(header, sealed)
		if err != nil || contentType != contentTypeApplicationData || string(plaintext) != "hello" {
			t.Fatalf("suite 0x%04x: got type %d %q %v", suite, contentType, plaintext, err)
		}
	}
}

func TestDecrypt12RecoversTheClientApplicationDataForEverySuite(t *testing.T) {
	messages := [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), bytes.Repeat([]byte("y"), 40000)}
	for _, suite := range []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	} {
		conn := handshakeAndSend(t, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}}, messages)
		if conn.serverHello.CipherSuites[0] != suite {
			t.Fatalf("server picked 0x%04x, want 0x%04x", conn.serverHello.CipherSuites[0], suite)
		}

		data, err := Decrypt12(conn.client, suite, conn.keys.Secret(MasterSecret, conn.clientHello.Random),
			conn.clientHello.Random, conn.serverHello.Random)
		if err != nil {
			t.Fatalf("suite 0x%04x: decrypt: %v", suite, err)
		}
		if want := bytes.Join(messages, nil); !bytes.Equal(data, want) {
			t.Fatalf("suite 0x%04x: decrypted %d bytes, want %d", suite, len(data), len(want))
		}
	}
}

func TestStreamsDropRetransmissionsAndStopAtAGap(t *testing.T) {
	streams := NewStreams()
	streams.SYN("flow", 999)
	streams.Add("flow", 1005, []byte("world"))
	streams.Add("flow", 1000, []byte("hello"))
	streams.Add("flow", 1000, []byte("hel"))
	streams.Add("flow", 1003, []byte("lowo"))
	streams.Add("flow", 1020, []byte("after a gap"))

	if got := string(streams.Stream("flow")); got != "helloworld" {
		t.Fatalf("stream is %q, want %q", got, "helloworld")
	}
}
