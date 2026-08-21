package chromehttp1

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func writtenHeaderNames(t *testing.T, request *http.Request) []string {
	t.Helper()

	var buffer bytes.Buffer
	if err := WriteRequest(&buffer, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	lines := strings.Split(buffer.String(), "\r\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, found := strings.Cut(line, ":")
		if !found {
			t.Fatalf("malformed header line %q", line)
		}
		names = append(names, name)
	}

	return names
}

func requestWithHeaders(t *testing.T, target string, names ...string) *http.Request {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, name := range names {
		request.Header.Set(name, "x")
	}

	return request
}

func TestChromeRequestReproducesTheDocumentOrder(t *testing.T) {
	request := requestWithHeaders(t, "https://example.com/",
		"Upgrade-Insecure-Requests", "User-Agent", "Accept-Language", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding")

	want := []string{
		"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept-Language",
		"Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
		"Accept-Encoding",
	}
	if got := writtenHeaderNames(t, request); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order =\n %v\nwant\n %v", got, want)
	}
}

func TestChromeRequestReproducesTheXHROrder(t *testing.T) {
	request := requestWithHeaders(t, "https://api.example.com/v1/items",
		"Client-Version", "X-Request-Id", "User-Agent", "Content-Type",
		"Accept-Language", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode",
		"Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Cookie")

	want := []string{
		"Host", "Connection", "Client-Version", "X-Request-Id", "User-Agent",
		"Content-Type", "Accept-Language", "Accept", "Origin", "Sec-Fetch-Site",
		"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Cookie",
	}
	if got := writtenHeaderNames(t, request); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order =\n %v\nwant\n %v", got, want)
	}
}

func TestChromeRequestReproducesTheWebSocketOrder(t *testing.T) {
	request := requestWithHeaders(t, "https://ws.example.com/ws",
		"Pragma", "Cache-Control", "User-Agent", "Accept-Language", "Upgrade", "Origin",
		"Sec-WebSocket-Version", "Accept-Encoding", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions")
	request.Header.Set("Connection", "Upgrade")

	want := []string{
		"Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Accept-Language",
		"Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Encoding", "Sec-WebSocket-Key",
		"Sec-WebSocket-Extensions",
	}
	if got := writtenHeaderNames(t, request); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order =\n %v\nwant\n %v", got, want)
	}
}

func TestChromeRequestIsNotAlphabetical(t *testing.T) {
	names := writtenHeaderNames(t, requestWithHeaders(t, "https://example.com/",
		"User-Agent", "Accept", "Accept-Encoding", "Cookie", "Referer"))

	sorted := true
	for index := 1; index < len(names); index++ {
		if names[index-1] > names[index] {
			sorted = false

			break
		}
	}
	if sorted {
		t.Fatalf("header order is alphabetical, that is the Go tell we are removing: %v", names)
	}
}

func TestChromeRequestKeepsHostFirstAndCookieLast(t *testing.T) {
	names := writtenHeaderNames(t, requestWithHeaders(t, "https://example.com/",
		"Cookie", "User-Agent", "Accept", "Zzz-Custom"))

	if names[0] != "Host" {
		t.Fatalf("first header = %q, chrome sends Host first", names[0])
	}
	if names[len(names)-1] != "Cookie" {
		t.Fatalf("last header = %q, chrome sends Cookie last", names[len(names)-1])
	}
}

func TestChromeRequestAddsConnectionAndContentLength(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("User-Agent", "x")

	var buffer bytes.Buffer
	if err := WriteRequest(&buffer, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	written := buffer.String()
	if !strings.Contains(written, "Connection: keep-alive\r\n") {
		t.Fatal("chrome sends Connection: keep-alive on http/1.1")
	}
	if !strings.Contains(written, "Content-Length: 5\r\n") {
		t.Fatal("content length missing for a body of 5 bytes")
	}
	if !strings.HasSuffix(written, "\r\n\r\nhello") {
		t.Fatalf("body was not written after the header block: %q", written)
	}
}

func TestChromeRequestReproducesTheAPIPostOrder(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/items", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, name := range []string{
		"X-Request-Id", "User-Agent", "Content-Type", "Accept-Language", "Accept",
		"Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
		"Accept-Encoding", "Cookie",
	} {
		request.Header.Set(name, "x")
	}

	want := []string{
		"Host", "Connection", "Content-Length", "X-Request-Id", "User-Agent",
		"Content-Type", "Accept-Language", "Accept", "Origin", "Sec-Fetch-Site",
		"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Cookie",
	}
	if got := writtenHeaderNames(t, request); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order =\n %v\nwant\n %v", got, want)
	}
}

func TestChromeRequestFindsNonCanonicalHeaderKeys(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://ws.example.com/ws", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header["Sec-WebSocket-Key"] = []string{"dGhlIHNhbXBsZSBub25jZQ=="}
	request.Header["Sec-WebSocket-Version"] = []string{"13"}
	request.Header.Set("User-Agent", "x")

	var buffer bytes.Buffer
	if err := WriteRequest(&buffer, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	written := buffer.String()
	if !strings.Contains(written, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") {
		t.Fatalf("a key stored with non-canonical casing lost its value:\n%s", written)
	}
	if !strings.Contains(written, "Sec-WebSocket-Version: 13\r\n") {
		t.Fatalf("Sec-WebSocket-Version missing:\n%s", written)
	}
}
