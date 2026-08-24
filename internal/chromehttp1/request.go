package chromehttp1

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

var chromeHTTP1NavigationHeaderOrder = []string{
	"Host",
	"Connection",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"Upgrade-Insecure-Requests",
	"",
	"User-Agent",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Storage-Access",
	"Referer",
	"Accept-Encoding",
	"Accept-Language",
	"Cookie",
}

var chromeHTTP1HeaderOrder = []string{
	"Host",
	"Connection",
	"Content-Length",
	"sec-ch-ua-platform",
	"Pragma",
	"Cache-Control",
	"",
	"User-Agent",
	"sec-ch-ua",
	"Content-Type",
	"sec-ch-ua-mobile",
	"Accept",
	"Upgrade",
	"Origin",
	"Sec-WebSocket-Version",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Storage-Access",
	"Referer",
	"Accept-Encoding",
	"Accept-Language",
	"Sec-WebSocket-Key",
	"Sec-WebSocket-Extensions",
	"Sec-WebSocket-Protocol",
	"Cookie",
}

func chromeHTTP1OrderFor(present map[string]bool) []string {
	if present["Upgrade-Insecure-Requests"] {
		return chromeHTTP1NavigationHeaderOrder
	}

	return chromeHTTP1HeaderOrder
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

	order := chromeHTTP1OrderFor(present)
	placed := make(map[string]bool, len(order))
	for _, name := range order {
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
	for _, name := range order {
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
	header.Del("Priority")
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
