package chromehttp1

import (
	"bufio"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

var chromeHTTP1HeaderOrder = []string{
	"Host",
	"Connection",
	"Content-Length",
	"Pragma",
	"Cache-Control",
	"Upgrade-Insecure-Requests",
	"",
	"User-Agent",
	"Content-Type",
	"Accept-Language",
	"Accept",
	"Upgrade",
	"Origin",
	"Sec-WebSocket-Version",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Referer",
	"Accept-Encoding",
	"Sec-WebSocket-Key",
	"Sec-WebSocket-Extensions",
	"Sec-WebSocket-Protocol",
	"Cookie",
}

func indexHeader(header http.Header) (map[string][]string, map[string]string) {
	values := make(map[string][]string, len(header))
	casing := make(map[string]string, len(header))
	for name, headerValues := range header {
		canonical := http.CanonicalHeaderKey(name)
		values[canonical] = append(values[canonical], headerValues...)
		casing[canonical] = name
	}

	return values, casing
}

func orderedHeaderNames(values map[string][]string, casing map[string]string, host string) []string {
	present := make(map[string]bool, len(values)+1)
	for canonical := range values {
		present[canonical] = true
	}
	if host != "" {
		present["Host"] = true
	}

	placed := make(map[string]bool, len(chromeHTTP1HeaderOrder))
	for _, name := range chromeHTTP1HeaderOrder {
		if name != "" {
			placed[http.CanonicalHeaderKey(name)] = true
		}
	}

	unordered := make([]string, 0, len(present))
	for canonical := range present {
		if !placed[canonical] {
			unordered = append(unordered, casing[canonical])
		}
	}
	sort.Strings(unordered)

	names := make([]string, 0, len(present))
	for _, name := range chromeHTTP1HeaderOrder {
		if name == "" {
			names = append(names, unordered...)
			continue
		}
		if present[http.CanonicalHeaderKey(name)] {
			names = append(names, name)
		}
	}

	return names
}

func WriteRequest(writer io.Writer, request *http.Request) error {
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}

	header := request.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	if header.Get("Connection") == "" {
		header.Set("Connection", "keep-alive")
	}
	if request.ContentLength > 0 && header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.FormatInt(request.ContentLength, 10))
	}

	values, casing := indexHeader(header)

	var builder strings.Builder
	builder.WriteString(request.Method)
	builder.WriteString(" ")
	builder.WriteString(request.URL.RequestURI())
	builder.WriteString(" HTTP/1.1\r\n")
	for _, name := range orderedHeaderNames(values, casing, host) {
		if name == "Host" {
			builder.WriteString("Host: ")
			builder.WriteString(host)
			builder.WriteString("\r\n")
			continue
		}
		for _, value := range values[http.CanonicalHeaderKey(name)] {
			builder.WriteString(name)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteString("\r\n")
		}
	}
	builder.WriteString("\r\n")

	if _, err := io.WriteString(writer, builder.String()); err != nil {
		return err
	}
	if request.Body == nil {
		return nil
	}
	defer request.Body.Close()
	_, err := io.Copy(writer, request.Body)

	return err
}

func RoundTrip(connection io.ReadWriteCloser, request *http.Request) (*http.Response, error) {
	if err := WriteRequest(connection, request); err != nil {
		connection.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		connection.Close()
		return nil, err
	}
	response.Body = &connectionClosingBody{ReadCloser: response.Body, connection: connection}

	return response, nil
}

type connectionClosingBody struct {
	io.ReadCloser
	connection io.Closer
}

func (b *connectionClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.connection.Close()

	return err
}
