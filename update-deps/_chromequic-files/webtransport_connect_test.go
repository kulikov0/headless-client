package http3

import (
	"net/http"
	"net/url"
	"testing"
)

func chromeWebTransportConnectRequest(t *testing.T) *http.Request {
	t.Helper()
	target, err := url.Parse("https://webtransport.example:4433/session?id=1")
	if err != nil {
		t.Fatalf("cannot parse the target: %v", err)
	}
	header := http.Header{}
	header["User-Agent"] = nil
	header["Origin"] = []string{"https://origin.example"}
	header["Sec-Webtransport-Http3-Draft02"] = []string{"1"}
	header[pHeaderOrderKey] = []string{":scheme", ":method", ":authority", ":path", ":protocol"}
	header[headerOrderKey] = []string{"sec-webtransport-http3-draft02", "origin"}
	return &http.Request{
		Method: http.MethodConnect,
		Header: header,
		Proto:  "webtransport",
		Host:   target.Host,
		URL:    target,
	}
}

func encodedFieldNames(t *testing.T, req *http.Request, addGzipHeader bool) []string {
	t.Helper()
	fields, err := newRequestWriter().encodeHeaders(req, addGzipHeader, "", -1, true)
	if err != nil {
		t.Fatalf("cannot encode the headers: %v", err)
	}
	names := make([]string, 0, len(fields))
	for _, field := range fields {
		names = append(names, field.Name)
	}
	return names
}

func TestWebTransportConnectSendsChromesHeaderBlock(t *testing.T) {
	want := []string{
		":scheme",
		":method",
		":authority",
		":path",
		":protocol",
		"sec-webtransport-http3-draft02",
		"origin",
	}
	got := encodedFieldNames(t, chromeWebTransportConnectRequest(t), false)
	if len(got) != len(want) {
		t.Fatalf("the block carries %d fields %v, chrome sends %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d is %q, chrome sends %q", i, got[i], want[i])
		}
	}
}

func TestOrderedHeadersHonourTheNilUserAgent(t *testing.T) {
	for _, name := range encodedFieldNames(t, chromeWebTransportConnectRequest(t), false) {
		if name == "user-agent" {
			t.Fatal("a nil User-Agent still emitted the default user-agent, which puts the library name on the wire")
		}
	}
}

func TestAnAbsentUserAgentStillGetsTheDefault(t *testing.T) {
	req := chromeWebTransportConnectRequest(t)
	delete(req.Header, "User-Agent")
	found := false
	for _, name := range encodedFieldNames(t, req, false) {
		if name == "user-agent" {
			found = true
		}
	}
	if !found {
		t.Fatal("an absent User-Agent lost the default, so suppression and absence are no longer distinguished")
	}
}

func TestTheHeaderOrderKeysKeepTheSpellingTheProfileDependsOn(t *testing.T) {
	if headerOrderKey != "Header-Order:" {
		t.Errorf("headerOrderKey is %q, Profile.WebTransportConnectHeader hardcodes %q", headerOrderKey, "Header-Order:")
	}
	if pHeaderOrderKey != "PHeader-Order:" {
		t.Errorf("pHeaderOrderKey is %q, Profile.WebTransportConnectHeader hardcodes %q", pHeaderOrderKey, "PHeader-Order:")
	}
}

func TestAnEmptyValuedHeaderIsStillOmitted(t *testing.T) {
	req := chromeWebTransportConnectRequest(t)
	req.Header["Origin"] = nil
	for _, name := range encodedFieldNames(t, req, false) {
		if name == "origin" {
			t.Fatal("an empty-valued header reached the wire")
		}
	}
}
