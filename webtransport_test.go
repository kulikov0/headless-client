package headless

import (
	"net/http"
	"testing"
)

const testOrigin = "https://origin.example"

func TestWebTransportConnectHeaderCarriesChromesSetAndOrder(t *testing.T) {
	header := ChromeWindows.WebTransportConnectHeader(testOrigin)

	if _, present := header["User-Agent"]; !present {
		t.Error("User-Agent is absent, so the writer will inject the library default instead of omitting it")
	}
	if values := header["User-Agent"]; len(values) != 0 {
		t.Errorf("User-Agent carries %v, it must be present and empty to suppress the default", values)
	}
	if got := header.Get("Sec-Webtransport-Http3-Draft02"); got != "1" {
		t.Errorf("sec-webtransport-http3-draft02 is %q, chrome sends %q", got, "1")
	}

	wantPseudo := []string{":scheme", ":method", ":authority", ":path", ":protocol"}
	assertOrder(t, header, "PHeader-Order:", wantPseudo)
	wantHeaders := []string{"sec-webtransport-http3-draft02", "origin"}
	assertOrder(t, header, "Header-Order:", wantHeaders)
}

func assertOrder(t *testing.T, header http.Header, key string, want []string) {
	t.Helper()
	got := header[key]
	if len(got) != len(want) {
		t.Fatalf("%s lists %v, chrome sends %v", key, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s position %d is %q, chrome sends %q", key, i, got[i], want[i])
		}
	}
}

func TestWebTransportConnectHeaderPassesTheOriginThrough(t *testing.T) {
	for _, origin := range []string{"https://origin.example", "https://another.example:8443"} {
		header := ChromeWindows.WebTransportConnectHeader(origin)
		if got := header.Get("Origin"); got != origin {
			t.Errorf("origin is %q, want the %q the caller passed", got, origin)
		}
	}
}

func TestWebTransportConnectHeaderNeverCarriesAcceptEncoding(t *testing.T) {
	header := ChromeWindows.WebTransportConnectHeader(testOrigin)
	if _, present := header["Accept-Encoding"]; present {
		t.Error("accept-encoding is set, chrome sends none on a webtransport connect")
	}
}
