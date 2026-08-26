package headless

import (
	"bufio"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func websocketUpgradeHeaderOrder(t *testing.T) []string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	written := make(chan []string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()

		var names []string
		reader := bufio.NewReader(connection)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if name, _, found := strings.Cut(line, ":"); found {
				names = append(names, name)
			}
		}
		written <- names
	}()

	dialer := ChromeWindows.WebSocketDialer(TLSOptions{})
	dialer.HandshakeTimeout = 5 * time.Second
	connection, _, err := dialer.Dial("ws://"+listener.Addr().String()+"/", ChromeWindows.Headers(DestWebSocket))
	if connection != nil {
		connection.Close()
	}
	if err != nil && strings.Contains(err.Error(), "duplicate header not allowed") {
		t.Fatalf("the dialer rejected a profile header: %v; websocket-chrome-handshake.patch no longer removes Sec-Websocket-Extensions from the forbidden list", err)
	}

	select {
	case names := <-written:
		return names
	case <-time.After(5 * time.Second):
		t.Fatal("the dialer never wrote an upgrade request")
	}

	return nil
}

func TestVendoredWebSocketWritesTheChromeHeaderOrder(t *testing.T) {
	names := websocketUpgradeHeaderOrder(t)

	positionOf := func(name string) int {
		return slices.IndexFunc(names, func(candidate string) bool {
			return strings.EqualFold(candidate, name)
		})
	}

	for _, pair := range []struct{ first, second string }{
		{"Connection", "User-Agent"},
		{"Pragma", "Cache-Control"},
		{"Sec-WebSocket-Key", "Sec-WebSocket-Extensions"},
	} {
		firstAt, secondAt := positionOf(pair.first), positionOf(pair.second)
		if firstAt < 0 || secondAt < 0 {
			t.Fatalf("upgrade request is missing %s or %s, got %v", pair.first, pair.second, names)
		}
		if firstAt > secondAt {
			t.Fatalf("%s came after %s; net/http writes User-Agent right after Host and sorts the rest alphabetically, so websocket-chrome-handshake.patch no longer routes the upgrade through chromehttp1.WriteRequest\n got: %v",
				pair.first, pair.second, names)
		}
	}
}

func TestVendoredWebSocketCarriesTheProfileExtensions(t *testing.T) {
	names := websocketUpgradeHeaderOrder(t)

	if !slices.ContainsFunc(names, func(candidate string) bool {
		return strings.EqualFold(candidate, "Sec-WebSocket-Extensions")
	}) {
		t.Fatalf("upgrade request carries no Sec-WebSocket-Extensions, chrome offers permessage-deflate\n got: %v", names)
	}
}
