package headlessclient

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
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

func (p Profile) HTTPClient() *http.Client {
	return &http.Client{Transport: &chromeRoundTripper{keyLog: sharedKeyLog()}}
}

func (p Profile) WebSocketDialer() *websocket.Dialer {
	keyLog := sharedKeyLog()
	dialer := *websocket.DefaultDialer
	dialer.NetDialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialChromeTLS(ctx, network, address, keyLog, []string{"http/1.1"})
	}
	return &dialer
}

func dialChromeTLS(ctx context.Context, network, address string, keyLog io.Writer, alpnOverride []string) (net.Conn, error) {
	rawConn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	serverName, _, err := net.SplitHostPort(address)
	if err != nil {
		serverName = address
	}
	config := &utls.Config{ServerName: serverName, KeyLogWriter: keyLog}

	var uConn *utls.UConn
	if alpnOverride == nil {
		uConn = utls.UClient(rawConn, config, utls.HelloChrome_Auto)
	} else {
		spec, specErr := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if specErr != nil {
			rawConn.Close()
			return nil, specErr
		}
		filtered := spec.Extensions[:0]
		for _, ext := range spec.Extensions {
			switch typed := ext.(type) {
			case *utls.ALPNExtension:
				typed.AlpnProtocols = alpnOverride
			case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
				continue
			}
			filtered = append(filtered, ext)
		}
		spec.Extensions = filtered
		uConn = utls.UClient(rawConn, config, utls.HelloCustom)
		if err := uConn.ApplyPreset(&spec); err != nil {
			rawConn.Close()
			return nil, err
		}
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uConn, nil
}

type chromeRoundTripper struct {
	keyLog io.Writer
}

func (t *chromeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Accept-Encoding") == "" {
		request.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	}

	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(request.URL.Hostname(), port)

	uConn, err := dialChromeTLS(request.Context(), "tcp", address, t.keyLog, nil)
	if err != nil {
		return nil, err
	}

	var response *http.Response
	if uConn.(*utls.UConn).ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		clientConn, connErr := (&http2.Transport{}).NewClientConn(uConn)
		if connErr != nil {
			uConn.Close()
			return nil, connErr
		}
		response, err = clientConn.RoundTrip(request)
	} else {
		oneShotTransport := &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return uConn, nil
			},
		}
		response, err = oneShotTransport.RoundTrip(request)
	}
	if err != nil {
		return nil, err
	}

	decompressResponse(response)
	return response, nil
}

func decompressResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	var decompressor io.Reader
	var extra io.Closer
	switch strings.ToLower(response.Header.Get("Content-Encoding")) {
	case "gzip":
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			return
		}
		decompressor, extra = reader, reader
	case "deflate":
		reader := flate.NewReader(response.Body)
		decompressor, extra = reader, reader
	case "br":
		decompressor = brotli.NewReader(response.Body)
	case "zstd":
		reader, err := zstd.NewReader(response.Body)
		if err != nil {
			return
		}
		readCloser := reader.IOReadCloser()
		decompressor, extra = readCloser, readCloser
	default:
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
