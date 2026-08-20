package headlessclient

import (
	"context"
	"io"
	"net"
	"regexp"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

var userAgentChromeVersion = regexp.MustCompile(`Chrome/(\d+)\.`)

func TestProfileClientHelloIDMatchesUserAgent(t *testing.T) {
	match := userAgentChromeVersion.FindStringSubmatch(ChromeWindows.UserAgent())
	if match == nil {
		t.Fatalf("user agent has no Chrome version: %q", ChromeWindows.UserAgent())
	}
	clientHelloID := ChromeWindows.ClientHelloID()
	if clientHelloID.Client != "Chrome" {
		t.Fatalf("client hello client = %q, want Chrome", clientHelloID.Client)
	}
	if clientHelloID.Version != match[1] {
		t.Fatalf("client hello version = %q, user agent says %q", clientHelloID.Version, match[1])
	}
}

func TestProfileZeroValueFallsBackToChromeAuto(t *testing.T) {
	var empty Profile
	if empty.ClientHelloID() != utls.HelloChrome_Auto {
		t.Fatalf("zero profile client hello = %+v, want HelloChrome_Auto", empty.ClientHelloID())
	}
}

func TestProfileBuildersDoNotMutateTheReceiver(t *testing.T) {
	derived := ChromeWindows.
		WithName("Other").
		WithUserAgent("ua").
		WithAcceptLanguage("en-US").
		WithClientHelloID(utls.HelloFirefox_120)

	if ChromeWindows.Name() != "ChromeWindows" || ChromeWindows.UserAgent() == "ua" {
		t.Fatal("builder mutated the shared ChromeWindows profile")
	}
	if ChromeWindows.ClientHelloID() != utls.HelloChrome_133 {
		t.Fatal("builder mutated the shared profile client hello")
	}
	if derived.Name() != "Other" || derived.UserAgent() != "ua" {
		t.Fatalf("derived profile did not take the new values: %q %q", derived.Name(), derived.UserAgent())
	}
	if derived.Headers(DestEmpty).Get("Accept-Language") != "en-US" {
		t.Fatalf("derived accept language = %q", derived.Headers(DestEmpty).Get("Accept-Language"))
	}
}

func TestProfileClientHelloIDReachesTheWire(t *testing.T) {
	chrome := captureClientHello(t, ChromeWindows)
	firefox := captureClientHello(t, ChromeWindows.WithClientHelloID(utls.HelloFirefox_120))

	if len(chrome) == 0 || len(firefox) == 0 {
		t.Fatal("captured an empty client hello")
	}
	if string(chrome) == string(firefox) {
		t.Fatal("profile client hello id does not reach the wire, both profiles sent the same bytes")
	}
}

func captureClientHello(t *testing.T, profile Profile) []byte {
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
		read, _ := io.ReadFull(conn, buffer[:5])
		if read < 5 {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := profile.dialTLS(ctx, "tcp", listener.Addr().String(), nil, nil)
	if err == nil {
		conn.Close()
	}

	select {
	case hello := <-captured:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the client hello")
		return nil
	}
}
