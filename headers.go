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

func (p Profile) Headers(dest RequestDest) http.Header {
	header := http.Header{}
	header.Set("User-Agent", p.userAgent)
	header.Set("Accept-Language", p.acceptLanguage)
	switch dest {
	case DestDocument:
		header.Set("Upgrade-Insecure-Requests", "1")
		header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		header.Set("Sec-Fetch-User", "?1")
		header.Set("Sec-Fetch-Dest", "document")
	case DestScript:
		header.Set("Accept", "*/*")
		header.Set("Sec-Fetch-Site", "cross-site")
		header.Set("Sec-Fetch-Mode", "no-cors")
		header.Set("Sec-Fetch-Dest", "script")
	case DestEmpty:
		header.Set("Accept", "*/*")
		header.Set("Sec-Fetch-Site", "same-site")
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
	case DestWebSocket:
		header.Set("Pragma", "no-cache")
		header.Set("Cache-Control", "no-cache")
		header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
	}
	return header
}
