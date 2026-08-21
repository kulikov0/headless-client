package headlessclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func specSignatureAlgorithms(t *testing.T, alpnOverride []string) []utls.SignatureScheme {
	t.Helper()
	spec, err := ChromeWindows.clientHelloSpec(alpnOverride)
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
		got := specSignatureAlgorithms(t, alpnOverride)
		if !slices.Equal(got, captured) {
			t.Fatalf("alpnOverride=%v signature algorithms = %v, chrome sends %v", alpnOverride, got, captured)
		}
	}
}

func TestSignatureAlgorithmsAreNotDuplicated(t *testing.T) {
	spec, err := ChromeWindows.clientHelloSpec(nil)
	if err != nil {
		t.Fatalf("clientHelloSpec: %v", err)
	}
	applyChromeSignatureAlgorithms(spec)

	got := specSignatureAlgorithms(t, nil)
	for _, algorithm := range chromePostQuantumSignatureAlgorithms {
		if slices.Contains(got[3:], algorithm) {
			t.Fatalf("%#04x appears twice after a second apply", algorithm)
		}
	}
}

func dialWithOptions(t *testing.T, address string, options TLSOptions) []byte {
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
	conn, err := ChromeWindows.dialTLS(ctx, "tcp", address, nil, nil, options)
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
	if _, err := ChromeWindows.dialTLS(context.Background(), "tcp", "example.com:443", nil, nil, options); err == nil {
		t.Fatal("dial error must surface")
	}
	if seen != "example.com:443" {
		t.Fatalf("dial callback got %q, want the original address so sni stays right", seen)
	}
}

func TestServerNameOverrideReachesTheClientHello(t *testing.T) {
	hello := dialWithOptions(t, "10.0.0.1:443", TLSOptions{ServerName: "example.com"})
	if !bytes.Contains(hello, []byte("example.com")) {
		t.Fatal("server name override missing from the client hello")
	}

	fromAddress := dialWithOptions(t, "example.com:443", TLSOptions{})
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

func TestWebSocketSpecDropsApplicationSettings(t *testing.T) {
	spec, err := ChromeWindows.clientHelloSpec([]string{"http/1.1"})
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
