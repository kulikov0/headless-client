package headlessclient

import "testing"

func TestWebSocketHeadersMatchTheChromeUpgrade(t *testing.T) {
	header := ChromeWindows.Headers(DestWebSocket)

	for _, name := range []string{"Pragma", "Cache-Control", "User-Agent", "Accept-Language", "Accept-Encoding"} {
		if header.Get(name) == "" {
			t.Fatalf("%s missing, chrome sends it on the websocket upgrade", name)
		}
	}
	for _, name := range []string{"Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User"} {
		if header.Get(name) != "" {
			t.Fatalf("%s present, chrome does not send it on the websocket upgrade", name)
		}
	}
	if header.Get("Sec-WebSocket-Extensions") != "permessage-deflate; client_max_window_bits" {
		t.Fatalf("Sec-WebSocket-Extensions = %q, chrome offers permessage-deflate; client_max_window_bits",
			header.Get("Sec-WebSocket-Extensions"))
	}
	if header.Get("User-Agent") != ChromeWindows.UserAgent() {
		t.Fatal("websocket user agent must come from the profile")
	}
}
