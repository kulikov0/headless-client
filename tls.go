package headless

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	http1 "github.com/kulikov0/headless-client/internal/chromehttp1"
	http2 "github.com/kulikov0/headless-client/internal/chromehttp2"
	"github.com/kulikov0/headless-client/websocket"
	utls "github.com/refraction-networking/utls"
)

var (
	keyLogOnce   sync.Once
	keyLogWriter io.Writer
)

func sharedKeyLog() io.Writer {
	keyLogOnce.Do(func() {
		path := os.Getenv("SSLKEYLOGFILE")
		if path == "" {
			return
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return
		}
		keyLogWriter = file
	})
	return keyLogWriter
}

func chromeDialer() *net.Dialer {
	return &net.Dialer{KeepAlive: tcpKeepAliveDisabled}
}

type TLSOptions struct {
	DialContext        func(ctx context.Context, network, address string) (net.Conn, error)
	ServerName         string
	InsecureSkipVerify bool
}

var sharedTransports sync.Map

func (p Profile) HTTPClient() *http.Client {
	return &http.Client{Transport: p.sharedTransport()}
}

func (p Profile) sharedTransport() http.RoundTripper {
	if transport, ok := sharedTransports.Load(p); ok {
		return transport.(http.RoundTripper)
	}
	transport, _ := sharedTransports.LoadOrStore(p, p.Transport(TLSOptions{}))

	return transport.(http.RoundTripper)
}

func (p Profile) Transport(options TLSOptions) http.RoundTripper {
	return &chromeRoundTripper{profile: p, keyLog: sharedKeyLog(), options: options}
}

func (p Profile) WebSocketDialer(options TLSOptions) *websocket.Dialer {
	keyLog := sharedKeyLog()
	dialer := *websocket.DefaultDialer
	dialer.Proxy = nil
	dialer.NetDialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return p.dialTLS(ctx, network, address, keyLog, []string{"http/1.1"}, options)
	}
	return &dialer
}

var chromePostQuantumSignatureAlgorithms = []utls.SignatureScheme{0x0904, 0x0905, 0x0906}

func applyChromeSignatureAlgorithms(spec *utls.ClientHelloSpec) {
	for _, extension := range spec.Extensions {
		signatureAlgorithms, ok := extension.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		merged := append([]utls.SignatureScheme{}, chromePostQuantumSignatureAlgorithms...)
		for _, algorithm := range signatureAlgorithms.SupportedSignatureAlgorithms {
			if !slices.Contains(chromePostQuantumSignatureAlgorithms, algorithm) {
				merged = append(merged, algorithm)
			}
		}
		signatureAlgorithms.SupportedSignatureAlgorithms = merged
	}
}

func (p Profile) clientHelloSpec(alpnOverride []string) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(p.ClientHelloID())
	if err != nil {
		return nil, err
	}
	if p.ClientHelloID().Client == utls.HelloChrome_Auto.Client {
		applyChromeSignatureAlgorithms(&spec)
	}
	if alpnOverride == nil {
		return &spec, nil
	}

	filtered := spec.Extensions[:0]
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.ALPNExtension:
			typed.AlpnProtocols = alpnOverride
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue
		}
		filtered = append(filtered, extension)
	}
	spec.Extensions = filtered

	return &spec, nil
}

func (p Profile) dialTLS(ctx context.Context, network, address string, keyLog io.Writer, alpnOverride []string, options TLSOptions) (net.Conn, error) {
	dialContext := options.DialContext
	if dialContext == nil {
		dialContext = chromeDialer().DialContext
	}
	rawConn, err := dialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	serverName := options.ServerName
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		serverName = host
	}
	config := &utls.Config{
		ServerName:         serverName,
		KeyLogWriter:       keyLog,
		InsecureSkipVerify: options.InsecureSkipVerify,
	}

	spec, err := p.clientHelloSpec(alpnOverride)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	uConn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		rawConn.Close()
		return nil, err
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uConn, nil
}

const (
	chromeMaxIdleConnectionsPerHost = 6
	chromeIdleConnectionTimeout     = 300 * time.Second
	tcpKeepAliveDisabled            = -1
)

type idleConnection struct {
	connection *http1.Conn
	expiresAt  time.Time
}

type chromeRoundTripper struct {
	profile        Profile
	keyLog         io.Writer
	options        TLSOptions
	http2Transport http2.Transport

	mu               sync.Mutex
	idleConnections  map[string][]idleConnection
	http2Connections map[string]*http2.ClientConn
}

func (t *chromeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Accept-Encoding") == "" {
		request.Header.Set("Accept-Encoding", chromeAcceptEncoding)
	}

	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(request.URL.Hostname(), port)

	response, reused, err := t.roundTripOnIdle(request, address)
	if err != nil && reused {
		replay, replayable := replayableRequest(request)
		if !replayable {
			return nil, err
		}
		request = replay
		response, err = nil, nil
	}
	if response == nil && err == nil {
		response, err = t.roundTripOnNew(request, address)
	}
	if err != nil {
		return nil, err
	}

	decompressResponse(response)
	return response, nil
}

func (t *chromeRoundTripper) roundTripOnIdle(request *http.Request, address string) (*http.Response, bool, error) {
	t.mu.Lock()
	clientConn := t.http2Connections[address]
	if clientConn != nil && !clientConn.CanTakeNewRequest() {
		delete(t.http2Connections, address)
		clientConn = nil
	}
	t.mu.Unlock()
	if clientConn != nil {
		response, err := clientConn.RoundTrip(request)
		return response, true, err
	}

	connection := t.takeIdle(address)
	if connection == nil {
		return nil, false, nil
	}
	response, err := connection.RoundTrip(request)
	if err != nil {
		connection.Close()
	}

	return response, true, err
}

func (t *chromeRoundTripper) roundTripOnNew(request *http.Request, address string) (*http.Response, error) {
	uConn, err := t.profile.dialTLS(request.Context(), "tcp", address, t.keyLog, nil, t.options)
	if err != nil {
		return nil, err
	}

	if uConn.(*utls.UConn).ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		clientConn, connErr := t.http2Transport.NewClientConn(uConn)
		if connErr != nil {
			uConn.Close()
			return nil, connErr
		}
		t.mu.Lock()
		if t.http2Connections == nil {
			t.http2Connections = map[string]*http2.ClientConn{}
		}
		t.http2Connections[address] = clientConn
		t.mu.Unlock()

		return clientConn.RoundTrip(request)
	}

	connection := http1.NewConn(uConn)
	connection.SetIdleHandler(func(idle *http1.Conn) { t.putIdle(address, idle) })
	response, err := connection.RoundTrip(request)
	if err != nil {
		connection.Close()
		return nil, err
	}

	return response, nil
}

func (t *chromeRoundTripper) takeIdle(address string) *http1.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for len(t.idleConnections[address]) > 0 {
		pool := t.idleConnections[address]
		last := pool[len(pool)-1]
		t.idleConnections[address] = pool[:len(pool)-1]
		if now.Before(last.expiresAt) && last.connection.Reusable() {
			return last.connection
		}
		last.connection.Close()
	}

	return nil
}

func (t *chromeRoundTripper) putIdle(address string, connection *http1.Conn) {
	if !connection.Reusable() {
		connection.Close()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.idleConnections == nil {
		t.idleConnections = map[string][]idleConnection{}
	}
	if len(t.idleConnections[address]) >= chromeMaxIdleConnectionsPerHost {
		connection.Close()
		return
	}
	t.idleConnections[address] = append(t.idleConnections[address], idleConnection{
		connection: connection,
		expiresAt:  time.Now().Add(chromeIdleConnectionTimeout),
	})
}

func (t *chromeRoundTripper) CloseIdleConnections() {
	t.mu.Lock()
	idle := t.idleConnections
	clientConns := t.http2Connections
	t.idleConnections = nil
	t.http2Connections = nil
	t.mu.Unlock()

	for _, pool := range idle {
		for _, entry := range pool {
			entry.connection.Close()
		}
	}
	for _, clientConn := range clientConns {
		clientConn.Close()
	}
}

func replayableRequest(request *http.Request) (*http.Request, bool) {
	if request.Body == nil || request.Body == http.NoBody {
		return request, true
	}
	if request.GetBody == nil {
		return nil, false
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, false
	}
	replay := request.Clone(request.Context())
	replay.Body = body

	return replay, true
}

type contentEncoding struct {
	name      string
	newReader func(io.Reader) (io.Reader, io.Closer, error)
}

var chromeContentEncodings = []contentEncoding{
	{"gzip", func(source io.Reader) (io.Reader, io.Closer, error) {
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, nil, err
		}

		return reader, reader, nil
	}},
	{"deflate", func(source io.Reader) (io.Reader, io.Closer, error) {
		reader := flate.NewReader(source)

		return reader, reader, nil
	}},
	{"br", func(source io.Reader) (io.Reader, io.Closer, error) {
		return brotli.NewReader(source), nil, nil
	}},
	{"zstd", func(source io.Reader) (io.Reader, io.Closer, error) {
		reader, err := zstd.NewReader(source)
		if err != nil {
			return nil, nil, err
		}
		readCloser := reader.IOReadCloser()

		return readCloser, readCloser, nil
	}},
}

var chromeAcceptEncoding = func() string {
	names := make([]string, len(chromeContentEncodings))
	for index, encoding := range chromeContentEncodings {
		names[index] = encoding.name
	}

	return strings.Join(names, ", ")
}()

func decompressResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	name := strings.ToLower(response.Header.Get("Content-Encoding"))
	index := slices.IndexFunc(chromeContentEncodings, func(encoding contentEncoding) bool {
		return encoding.name == name
	})
	if index < 0 {
		return
	}
	decompressor, extra, err := chromeContentEncodings[index].newReader(response.Body)
	if err != nil {
		return
	}

	response.Body = &wrappedBody{decompressor: decompressor, source: response.Body, extra: extra}
	response.Header.Del("Content-Encoding")
	response.Header.Del("Content-Length")
	response.ContentLength = -1
}

type wrappedBody struct {
	decompressor io.Reader
	source       io.ReadCloser
	extra        io.Closer
}

func (w *wrappedBody) Read(p []byte) (int, error) {
	return w.decompressor.Read(p)
}

func (w *wrappedBody) Close() error {
	if w.extra != nil {
		w.extra.Close()
	}
	return w.source.Close()
}
