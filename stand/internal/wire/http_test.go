package wire

import (
	"bytes"
	"slices"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func chromeLikeHTTP2Session(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	buffer.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&buffer, nil)

	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
	if err := framer.WriteSettings(settings...); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := framer.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatalf("write window update: %v", err)
	}

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "sec-ch-ua-mobile", Value: "?0"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
	} {
		encoder.WriteField(field)
	}
	err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: block.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
		Priority:      http2.PriorityParam{Exclusive: true, Weight: 255},
	})
	if err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := framer.WriteSettingsAck(); err != nil {
		t.Fatalf("write settings ack: %v", err)
	}
	return buffer.Bytes()
}

func TestParseHTTP2ReadsTheConnectionPrefaceAndTheFirstRequest(t *testing.T) {
	session, err := ParseSession(chromeLikeHTTP2Session(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if session.Protocol != ProtocolHTTP2 {
		t.Fatalf("protocol is %q", session.Protocol)
	}
	if want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"; session.Akamai() != want {
		t.Fatalf("akamai is %q, want %q", session.Akamai(), want)
	}
	if len(session.Requests) != 1 {
		t.Fatalf("got %d requests", len(session.Requests))
	}
	request := session.Requests[0]
	if request.Priority == nil || !request.Priority.Exclusive || request.Priority.Weight != 255 {
		t.Fatalf("headers priority is %+v, want exclusive weight 255", request.Priority)
	}
	var names []string
	for _, field := range request.Headers {
		names = append(names, field.Name)
	}
	if want := []string{":method", ":authority", ":scheme", ":path", "sec-ch-ua-mobile", "user-agent"}; !slices.Equal(names, want) {
		t.Fatalf("header order is %v, want %v", names, want)
	}
}

func TestParseHTTP2StopsCleanlyOnATruncatedFrame(t *testing.T) {
	data := chromeLikeHTTP2Session(t)
	session, err := ParseSession(data[:len(data)-12])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(session.Settings) != 4 || session.WindowUpdate != 15663105 {
		t.Fatalf("lost the frames before the truncation: %+v", session)
	}
}

func TestParseHTTP1KeepsHeaderCaseAndOrder(t *testing.T) {
	session, err := ParseSession([]byte("GET /ws HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n\x81\x05hello"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	request := session.Requests[0]
	if request.RequestLine != "GET /ws HTTP/1.1" || len(request.Headers) != 2 || request.Headers[1].Name != "User-Agent" {
		t.Fatalf("got %+v", request)
	}
}

func TestParseHTTPRejectsSomethingElse(t *testing.T) {
	if _, err := ParseSession([]byte("\x16\x03\x01 not http")); err == nil {
		t.Fatal("parsed binary data as http")
	}
}
