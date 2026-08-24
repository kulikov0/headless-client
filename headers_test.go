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

func TestRequestDestSecFetchSiteMatchesTheRoutesWeUse(t *testing.T) {
	routes := []struct {
		dest      RequestDest
		initiator string
		target    string
		want      string
	}{
		{DestDocument, "", "https://telemost.yandex.ru/", "none"},
		{DestScript, "https://telemost.yandex.ru/", "https://telemost.yastatic.net/s3/telemost/_/main.js", "cross-site"},
		{DestEmpty, "https://telemost.yandex.ru", "https://cloud-api.yandex.ru/telemost_front/v2/telemost", "same-site"},
	}

	for _, route := range routes {
		got := ChromeWindows.Headers(route.dest).Get("Sec-Fetch-Site")
		if got != route.want {
			t.Fatalf("dest %d from %q to %q sends %q, chrome sends %q",
				route.dest, route.initiator, route.target, got, route.want)
		}
	}
}

func TestClientHintsRideEveryDestExceptTheWebSocketUpgrade(t *testing.T) {
	hints := []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

	for _, dest := range []RequestDest{DestDocument, DestScript, DestEmpty} {
		header := ChromeWindows.Headers(dest)
		for _, name := range hints {
			if header.Get(name) == "" {
				t.Fatalf("dest %d omits %s, chrome sends it on every secure request", dest, name)
			}
		}
	}

	upgrade := ChromeWindows.Headers(DestWebSocket)
	for _, name := range hints {
		if upgrade.Get(name) != "" {
			t.Fatalf("websocket upgrade carries %s, the chrome upgrade carries no client hints", name)
		}
	}
}

func TestClientHintValuesMatchTheProfilePlatform(t *testing.T) {
	header := ChromeWindows.Headers(DestEmpty)

	if got := header.Get("sec-ch-ua"); got != `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"` {
		t.Fatalf("sec-ch-ua = %q", got)
	}
	if got := header.Get("sec-ch-ua-mobile"); got != "?0" {
		t.Fatalf("sec-ch-ua-mobile = %q, a desktop profile sends ?0", got)
	}
	if got := header.Get("sec-ch-ua-platform"); got != `"Windows"` {
		t.Fatalf("sec-ch-ua-platform = %q, the profile claims Windows", got)
	}
}

func TestPriorityMatchesTheMeasuredUrgencyPerDest(t *testing.T) {
	priorities := map[RequestDest]string{
		DestDocument:  "u=0, i",
		DestScript:    "u=1",
		DestEmpty:     "u=1, i",
		DestWebSocket: "",
	}

	for dest, want := range priorities {
		if got := ChromeWindows.Headers(dest).Get("Priority"); got != want {
			t.Fatalf("dest %d sends priority %q, chrome sends %q", dest, got, want)
		}
	}
}

func TestWebSocketDestCarriesNoFetchMetadata(t *testing.T) {
	header := ChromeWindows.Headers(DestWebSocket)
	for _, name := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Accept"} {
		if header.Get(name) != "" {
			t.Fatalf("websocket upgrade carries %s, the chrome upgrade carries none of them", name)
		}
	}
}
