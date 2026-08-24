package headlessclient

import "net/http"

type RequestDest int

const (
	DestDocument RequestDest = iota
	DestScript
	DestEmpty
	DestWebSocket
)

func (p Profile) UserAgent() string {
	return p.userAgent
}

type headerValue struct {
	name  string
	value string
}

var chromeDestHeaders = map[RequestDest][]headerValue{
	DestDocument: {
		{"Upgrade-Insecure-Requests", "1"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Priority", "u=0, i"},
	},
	DestScript: {
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Mode", "no-cors"},
		{"Sec-Fetch-Dest", "script"},
		{"Sec-Fetch-Storage-Access", "none"},
		{"Priority", "u=1"},
	},
	DestEmpty: {
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "same-site"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Priority", "u=1, i"},
	},
	DestWebSocket: {
		{"Pragma", "no-cache"},
		{"Cache-Control", "no-cache"},
		{"Accept-Encoding", chromeAcceptEncoding},
		{"Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits"},
	},
}

func (p Profile) Headers(dest RequestDest) http.Header {
	header := http.Header{}
	header.Set("User-Agent", p.userAgent)
	header.Set("Accept-Language", p.acceptLanguage)
	if dest != DestWebSocket {
		header.Set("sec-ch-ua", p.clientHintBrands)
		header.Set("sec-ch-ua-mobile", p.clientHintMobile)
		header.Set("sec-ch-ua-platform", p.clientHintPlatform)
	}
	for _, entry := range chromeDestHeaders[dest] {
		header.Set(entry.name, entry.value)
	}

	return header
}
