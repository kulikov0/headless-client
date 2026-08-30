package headless

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func specSignatureAlgorithms(t *testing.T, profile Profile, alpnOverride []string) []utls.SignatureScheme {
	t.Helper()
	spec, err := profile.clientHelloSpec(alpnOverride, false)
	if err != nil {
		t.Fatalf("clientHelloSpec: %v", err)
	}
	for _, extension := range spec.Extensions {
		if signatureAlgorithms, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
			return signatureAlgorithms.SupportedSignatureAlgorithms
		}
	}
	t.Fatal("no signature algorithms extension in the spec")

	return nil
}

func TestSignatureAlgorithmsMatchTheChromeCapture(t *testing.T) {
	captured := []utls.SignatureScheme{
		0x0904, 0x0905, 0x0906,
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
		utls.PKCS1WithSHA256,
		utls.ECDSAWithP384AndSHA384,
		utls.PSSWithSHA384,
		utls.PKCS1WithSHA384,
		utls.PSSWithSHA512,
		utls.PKCS1WithSHA512,
	}

	for _, alpnOverride := range [][]string{nil, {"http/1.1"}} {
		got := specSignatureAlgorithms(t, ChromeWindows, alpnOverride)
		if !slices.Equal(got, captured) {
			t.Fatalf("alpnOverride=%v signature algorithms = %v, chrome sends %v", alpnOverride, got, captured)
		}
	}
}

func TestNonChromeParrotKeepsItsOwnSignatureAlgorithms(t *testing.T) {
	firefox := ChromeWindows.WithClientHelloID(utls.HelloFirefox_120)
	for _, algorithm := range specSignatureAlgorithms(t, firefox, nil) {
		if slices.Contains(chromePostQuantumSignatureAlgorithms, algorithm) {
			t.Fatalf("firefox parrot carries the chrome signature algorithm %#04x", algorithm)
		}
	}
}

func TestSignatureAlgorithmsAreNotDuplicated(t *testing.T) {
	spec, err := ChromeWindows.clientHelloSpec(nil, false)
	if err != nil {
		t.Fatalf("clientHelloSpec: %v", err)
	}
	applyChromeSignatureAlgorithms(spec)

	got := specSignatureAlgorithms(t, ChromeWindows, nil)
	for _, algorithm := range chromePostQuantumSignatureAlgorithms {
		if slices.Contains(got[3:], algorithm) {
			t.Fatalf("%#04x appears twice after a second apply", algorithm)
		}
	}
}

func dialWithOptions(t *testing.T, address string, options TLSOptions, sessionCache utls.ClientSessionCache) []byte {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	captured := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			captured <- nil
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 4096)
		if _, readErr := io.ReadFull(conn, buffer[:5]); readErr != nil {
			captured <- nil
			return
		}
		length := int(buffer[3])<<8 | int(buffer[4])
		if length > len(buffer)-5 {
			captured <- nil
			return
		}
		if _, readErr := io.ReadFull(conn, buffer[5:5+length]); readErr != nil {
			captured <- nil
			return
		}
		captured <- buffer[:5+length]
	}()

	if options.DialContext == nil {
		options.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ChromeWindows.dialTLS(ctx, "tcp", address, nil, nil, sessionCache, options)
	if err == nil {
		conn.Close()
	}

	select {
	case hello := <-captured:
		if hello == nil {
			t.Fatal("nothing captured")
		}
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the client hello")
		return nil
	}
}

func TestDialContextReceivesTheOriginalAddress(t *testing.T) {
	var seen string
	options := TLSOptions{
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			seen = address
			return nil, io.EOF
		},
	}
	if _, err := ChromeWindows.dialTLS(context.Background(), "tcp", "example.com:443", nil, nil, nil, options); err == nil {
		t.Fatal("dial error must surface")
	}
	if seen != "example.com:443" {
		t.Fatalf("dial callback got %q, want the original address so sni stays right", seen)
	}
}

func TestServerNameOverrideReachesTheClientHello(t *testing.T) {
	hello := dialWithOptions(t, "10.0.0.1:443", TLSOptions{ServerName: "example.com"}, nil)
	if !bytes.Contains(hello, []byte("example.com")) {
		t.Fatal("server name override missing from the client hello")
	}

	fromAddress := dialWithOptions(t, "example.com:443", TLSOptions{}, nil)
	if !bytes.Contains(fromAddress, []byte("example.com")) {
		t.Fatal("server name should fall back to the dialled address")
	}
}

func TestWebSocketDialerIgnoresTheEnvironmentProxy(t *testing.T) {
	dialer := ChromeWindows.WebSocketDialer(TLSOptions{})
	if dialer.Proxy != nil {
		t.Fatal("egress must come from TLSOptions.DialContext, not from HTTPS_PROXY")
	}
}

func countingTLSServer(t *testing.T, http2Enabled bool, handler http.HandlerFunc) (string, *atomic.Int64) {
	t.Helper()

	var connections atomic.Int64
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = http2Enabled
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "https://"), &connections
}

func pooledClient(address string) *http.Client {
	return &http.Client{Transport: ChromeWindows.Transport(TLSOptions{
		InsecureSkipVerify: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	})}
}

func drainRequests(t *testing.T, client *http.Client, count int) {
	t.Helper()

	for attempt := 0; attempt < count; attempt++ {
		response, err := client.Get("https://example.com/")
		if err != nil {
			t.Fatalf("request %d: %v", attempt, err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
}

func TestTransportReusesOneHTTP1Connection(t *testing.T) {
	address, connections := countingTLSServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})

	drainRequests(t, pooledClient(address), 5)

	if got := connections.Load(); got != 1 {
		t.Fatalf("opened %d connections for 5 requests, chrome keeps one for 300s", got)
	}
}

func TestTransportReusesOneHTTP2Connection(t *testing.T) {
	address, connections := countingTLSServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})

	drainRequests(t, pooledClient(address), 5)

	if got := connections.Load(); got != 1 {
		t.Fatalf("opened %d connections for 5 requests, h2 multiplexes over one", got)
	}
}

func TestTransportDoesNotPoolAConnectionTheServerClosed(t *testing.T) {
	address, connections := countingTLSServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "ok")
	})

	drainRequests(t, pooledClient(address), 3)

	if got := connections.Load(); got != 3 {
		t.Fatalf("opened %d connections, a Connection: close response must not be pooled", got)
	}
}

func TestCloseIdleConnectionsDropsThePool(t *testing.T) {
	address, connections := countingTLSServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})

	client := pooledClient(address)
	drainRequests(t, client, 2)
	client.CloseIdleConnections()
	drainRequests(t, client, 2)

	if got := connections.Load(); got != 2 {
		t.Fatalf("opened %d connections, want 1 before and 1 after the pool was dropped", got)
	}
}

func TestTransportReturnsAPoolTheCallerOwns(t *testing.T) {
	first := ChromeWindows.Transport(TLSOptions{})
	second := ChromeWindows.Transport(TLSOptions{})
	if first == second {
		t.Fatal("Transport returned the same round tripper twice, each call must own its pool")
	}

	shared := ChromeWindows.HTTPClient().Transport
	if shared == first || shared == second {
		t.Fatal("HTTPClient handed back a transport built by Transport, the shared pool must stay separate")
	}
}

func TestHTTPClientSharesOnePoolPerProfile(t *testing.T) {
	first := ChromeWindows.HTTPClient()
	second := ChromeWindows.HTTPClient()
	if first.Transport != second.Transport {
		t.Fatal("a client built per request must still reuse the pool")
	}

	other := ChromeWindows.WithName("other").HTTPClient()
	if other.Transport == first.Transport {
		t.Fatal("distinct profiles must not share a pool")
	}

	if ChromeWindows.Transport(TLSOptions{}) == ChromeWindows.Transport(TLSOptions{}) {
		t.Fatal("Transport returns a pool the caller owns, it must not be shared")
	}
}

func TestWebSocketSpecDropsApplicationSettings(t *testing.T) {
	spec, err := ChromeWindows.clientHelloSpec([]string{"http/1.1"}, false)
	if err != nil {
		t.Fatalf("clientHelloSpec: %v", err)
	}
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			t.Fatal("application settings must not be offered without h2")
		case *utls.ALPNExtension:
			if !slices.Equal(typed.AlpnProtocols, []string{"http/1.1"}) {
				t.Fatalf("alpn = %v, want http/1.1 only", typed.AlpnProtocols)
			}
		}
	}
}

func TestTransportResumesTheTLSSessionOnANewConnection(t *testing.T) {
	var mutex sync.Mutex
	var resumed []bool
	var versions []uint16
	address, _ := countingTLSServer(t, false, func(_ http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		resumed = append(resumed, request.TLS.DidResume)
		versions = append(versions, request.TLS.Version)
		mutex.Unlock()
	})

	transport := ChromeWindows.Transport(TLSOptions{
		InsecureSkipVerify: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	})
	client := &http.Client{Transport: transport}
	drainRequests(t, client, 1)
	transport.(*chromeRoundTripper).CloseIdleConnections()
	drainRequests(t, client, 1)

	mutex.Lock()
	defer mutex.Unlock()

	if len(resumed) != 2 {
		t.Fatalf("the server handled %d requests, want 2", len(resumed))
	}
	if versions[1] != tls.VersionTLS13 {
		t.Fatalf("the second connection negotiated 0x%04x, the resumed chrome ja4 is a 1.3 pre_shared_key handshake", versions[1])
	}
	if resumed[0] {
		t.Fatal("the first connection resumed, so the fixture proves nothing")
	}
	if !resumed[1] {
		t.Fatal("the second connection ran a full handshake; chrome resumes and emits a second ja4 carrying pre_shared_key, and without a session cache we never produce that variant")
	}
}

func clientHelloExtensionTypes(t *testing.T, record []byte) []uint16 {
	t.Helper()

	if len(record) < 5+4+2+32+1 {
		t.Fatalf("captured %d bytes, too short for a client hello", len(record))
	}
	body := record[5+4+2+32:]
	body = body[1+int(body[0]):]
	body = body[2+(int(body[0])<<8|int(body[1])):]
	body = body[1+int(body[0]):]
	body = body[2:]

	types := make([]uint16, 0, 20)
	for len(body) >= 4 {
		length := int(body[2])<<8 | int(body[3])
		if len(body) < 4+length {
			t.Fatalf("extension %d claims %d bytes but %d remain", uint16(body[0])<<8|uint16(body[1]), length, len(body)-4)
		}
		types = append(types, uint16(body[0])<<8|uint16(body[1]))
		body = body[4+length:]
	}

	return types
}

func normalizeGREASE(types []uint16) {
	for index, value := range types {
		if slices.Contains(greaseValues[:], value) {
			types[index] = greaseValues[0]
		}
	}
}

func TestAFreshClientHelloOmitsTheEmptyPreSharedKey(t *testing.T) {
	const preSharedKey = uint16(41)

	withoutCache := dialWithOptions(t, "example.com:443", TLSOptions{}, nil)
	withCache := dialWithOptions(t, "example.com:443", TLSOptions{}, utls.NewLRUClientSessionCache(0))

	offered := clientHelloExtensionTypes(t, withCache)
	if slices.Contains(offered, preSharedKey) {
		t.Fatalf("a fresh client hello offers an empty pre_shared_key, chrome omits it; extensions %v", offered)
	}
	baseline := clientHelloExtensionTypes(t, withoutCache)
	normalizeGREASE(offered)
	normalizeGREASE(baseline)
	slices.Sort(offered)
	slices.Sort(baseline)
	if !slices.Equal(offered, baseline) {
		t.Fatalf("the session cache changed the extension set to %v from %v", offered, baseline)
	}
}
