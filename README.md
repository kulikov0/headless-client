# headless-client

headless-client is a Go library. It makes a Go client send the same network
fingerprint as Chrome.

A Go client has a fingerprint of its own, from the standard library and from the
packages it builds on:

- `crypto/tls` sends a Go TLS ClientHello.
- `x/net/http2` sends a Go HTTP/2 SETTINGS frame and sorts headers
  alphabetically.
- pion sends a pion DTLS ClientHello.
- `net.Dialer` enables a TCP keepalive timer.

Any of these identifies the client as a Go process. This library replaces them
with the Chrome equivalents.

## Status

The library is in development. The API is unstable and changes without notice.
One profile is available: Chrome 151 on Windows.

## Installation

Go 1.26.1 or later is required.

```
go get github.com/kulikov0/headless-client
```

```go
import "github.com/kulikov0/headless-client"
```

The package is named `headless`.

## Use cases

- Network security research. Measure which surfaces let a passive observer
  distinguish a browser from a non-browser client.
- Crawling and scraping. The HTTP part covers JA3 and JA4, HTTP/2 SETTINGS,
  header order, the priority header and connection reuse, and it works without
  the WebRTC part.
- Testing services that handle non-browser clients differently.

## What it covers

- TLS: Chrome ClientHello through utls, post-quantum signature algorithms.
- HTTP/1.1 and HTTP/2: header order per request destination, Chrome SETTINGS and
  window sizes, pseudo-header order, the RFC 9218 priority header, a connection
  pool with Chrome's per-host limit and idle timeout.
- Headers: user agent, client hints, Accept, Accept-Encoding, Sec-Fetch-*.
- WebSocket: the Chrome upgrade handshake.
- WebRTC: DTLS ClientHello shuffling and GREASE, optional DTLS 1.3 mimicry, SRTP
  profile order, ICE credential shape, ICE keepalive interval.
- TCP: keepalive disabled, as in Chrome.

## Usage

### HTTP

`HTTPClient` returns an `http.Client` with the Chrome TLS, HTTP/2 and connection
pool settings applied.

```go
client := headless.ChromeWindows.HTTPClient()
```

Every call with the same profile returns a client backed by the same transport,
so connections are pooled across call sites. `client.CloseIdleConnections()`
drops that pool.

`Headers` returns the header set for a request destination.

```go
request.Header = headless.ChromeWindows.Headers(headless.DestEmpty)
```

The destinations are `DestDocument`, `DestScript`, `DestEmpty` and
`DestWebSocket`. The destination selects the Accept value, the Sec-Fetch-*
values and the priority value.

`Transport` returns a new transport on every call and takes dial options.

```go
transport := headless.ChromeWindows.Transport(headless.TLSOptions{
	DialContext: proxyDialer.DialContext,
	ServerName:  "example.com",
})
```

`TLSOptions` has three fields. `DialContext` replaces the TCP dial, which is
where a proxy goes. `ServerName` overrides the SNI value. `InsecureSkipVerify`
disables certificate verification.

`HTTPClient` takes no options because it keys its shared transport on the
profile value, and a function field cannot be part of a map key. Use `Transport`
when options are needed.

### WebSocket

```go
dialer := headless.ChromeWindows.WebSocketDialer(headless.TLSOptions{})
```

The dialer ignores the `HTTP_PROXY` and `HTTPS_PROXY` environment variables.
Pass a proxy through `TLSOptions.DialContext`.

### WebRTC

`SettingEngine` returns a `webrtc.SettingEngine` with the profile applied.

```go
settingEngine, err := headless.ChromeWindows.SettingEngine()
if err != nil {
	return err
}
settingEngine.DetachDataChannels()

api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))
```

Apply caller settings after the call. A pion setting applied later overwrites an
earlier one.

### Profiles

`headless.ChromeWindows` is the only profile. Each builder returns a copy with
one part changed and leaves the receiver alone.

```go
profile := headless.ChromeWindows.
	WithAcceptLanguage("en-US,en;q=0.9").
	WithDTLS13Mimicry()
```

- `WithDTLS13Mimicry` is for peers that negotiate DTLS 1.3. It turns off the
  ClientHello shuffle and the GREASE extension, and sends the Chrome DTLS 1.3
  extension order and cipher suite list.
- `WithClientHelloID` selects a different utls parrot.
- `WithUserAgent` and `WithAcceptLanguage` replace those header values.
- `WithName` sets the string returned by `Name`.

`UserAgent` and `ClientHelloID` return the current values.

A `Profile` is a comparable value. Two profiles with the same fields share one
connection pool.

### TLS key log

If `SSLKEYLOGFILE` is set, the library appends TLS session keys to that file, so
Wireshark can decrypt the capture. The file is opened once per process.

## Method

Values come from Chromium and libwebrtc source. Packet captures verify them.

A value copied from a capture, such as a JA3 string or a `sec-ch-ua` header,
describes one Chrome build. The next Chrome release changes it. This library
ports the code that produces the value. Changing `measuredChromeMajorVersion` in
`profile.go` regenerates the `sec-ch-ua` brand list. The `priority` values are
derived from the blink-to-net priority chain, so they cover request destinations
that were never captured.

The TLS ClientHello starts from the utls Chrome 133 parrot, the newest Chrome
parrot utls ships. Chrome 151 sends three signature algorithms that the parrot
does not, `0x0904`, `0x0905` and `0x0906`, so the library prepends them. The
rest of the ClientHello needs no patch. Against a Chrome 151 capture the
extension set, the groups and the cipher list match, and the JA4 fingerprints
are equal.

The `stand` directory contains a Docker capture stand. It runs a pinned Chromium
and a client built with this library in separate network namespaces, and diffs
their traffic.

## Tests

```
go test ./...
```

The tests check the values the library produces.

- The client hint tests reproduce Chromium's brand generator across versions.
- The header tests check the order and the values for each request destination.
- The DTLS tests run the ClientHello hook over a pion ClientHello and read back
  the extension order, the GREASE extension and the cipher suite list.
- The ICE test builds a peer connection and reads the credential lengths out of
  the offer.
- The transport tests run against a local server and check connection reuse.

Every vendored patch has a guard test that fails when a regeneration loses it.
`internal/chromehttp2` keeps its guards inside the tree, and `chromehttp2.sh`
copies them back after each run. The guards for `internal/dtls`, `internal/ice`
and `websocket` are in the root package, because those scripts delete every test
file in the tree they rewrite.

## Known gaps

The following gaps are scheduled. Gaps that will not be addressed are under
[Out of scope](#out-of-scope).

### HTTP

- HTTP/3 and QUIC are not implemented.
- Accept-Language is fixed to ru-RU. Chrome reads this value from a per-locale
  resource rather than deriving it, so a table is required.
- sec-ch-ua-platform is the only client hint value that was not read from
  Chromium source. The code branch that produces it is confirmed. The Windows
  spelling is not.

### TLS

- No TLS session cache is set, so every connection performs a full handshake.
  Chrome produces a second JA4 per host for resumed connections, with one
  additional extension, `pre_shared_key`. This library never produces that
  variant.

### WebRTC

- The SDP has pion's shape. The CNAME is derived from the stream ID, where
  Chrome uses a random value. The codec set and payload types are pion defaults.
  The header extension set is sparse. The attribute order is pion's. A server
  that reads the offer can detect all of this.
- No STUN keepalive is sent to the STUN server. Chrome sends one every 10 s in
  addition to the peer keepalive. Over a 170 s capture this library sent two
  packets to its STUN servers, both during gathering, and nothing after.
- The DTLS ClientHello is fragmented at a different boundary. Chrome sizes the
  first fragment so that the datagram is 1200 bytes. pion applies its MTU to the
  handshake payload and then adds the record and handshake headers. For the same
  1413 byte ClientHello Chrome sends datagrams of 1208 and 271 bytes, and this
  library sends 1233 and 246.
- RTCP feedback format and cadence have not been audited.
- The ICE candidate priority is one number that packs the candidate type, a
  local preference and the component. pion always writes 65535 as the local
  preference, so a host candidate gets 2130706431 where the reference capture
  shows 2122260223. A server that reads the offer sees it, and so does anyone
  reading a STUN binding request. Chrome's local preference there was 32542.
  Where that value comes from was not established, so there is no target to
  patch pion to yet.

### Behavior

- The profile reports Windows. The TCP and IP layers report the real host OS.
  Run the client on the operating system that the profile names. Profiles for
  other platforms are planned.
- The client sends no speculative traffic. Chrome preconnects, prefetches, and
  requests favicons and revocation lists. The planned fix is to replay a real
  page load, using the request destinations and priorities in this library.

## Out of scope

- Headers added by the caller sort after the Chrome headers. Chrome's order for
  an arbitrary header set follows a hash bucket order, which cannot be
  reproduced from a table.
- TURN over DTLS uses upstream pion without a ClientHello hook, so that
  handshake is not mimicked. libwebrtc implements this transport, so a server
  that offers it would see a pion handshake where Chrome sends its own. The
  branch runs only on a `turns:` URL with `transport=udp`, which no server in
  the measured traffic hands out, and a bare `turns:` resolves to TCP.
- Host ICE candidates are not hidden behind mDNS `.local` names. Chrome hides
  them only when the origin has no media permission, so the behaviour differs
  between calls. One reference capture carries 214 candidates and none is mDNS.
  In another, the remote peer offered two `.local` candidates and this library
  resolved them over mDNS. Hiding our own unconditionally would be wrong for the
  first case, and the condition that decides it is not visible from our side.

## Open questions

The ICE keepalive interval is set to 2656 ms, a measured value. libwebrtc sets
`kStrongAndStableWritableConnectionPingInterval` to 2500 ms, and reading the
scheduler in `wrapping_active_ice_controller.cc` predicts 2500 ms. The 156 ms
difference has no explanation.

Four causes were ruled out by measurement.

- RTT. The value is the same at 0.05 ms and at 60 ms.
- Capture noise. The standard deviation of the period is smaller than the RTT
  spread of the path.
- Timer drift. The offset is the same on a Mac and in a Linux container.
- A bimodal distribution hidden by the mean. The medians agree.

The measurement covers five datasets, two machines and three services, with
medians within 0.5 ms. All reference captures are Chrome on Linux, and the
profile reports Windows.

This library is configured for 2656 ms. The measured median is 2657 ms, over 65
intervals on each of two peer connections. The ICE task loop resets its timer
after the task runs, which adds the extra millisecond.

## Layout

`internal/dtls`, `internal/ice`, `internal/chromehttp2`, `webrtc`, and
`websocket` are vendored. They are copies of upstream packages with fingerprint
patches applied. Do not edit them by hand. Run the scripts in `update-deps` to
regenerate them. Guard tests fail if a regenerated tree loses a patch.

`internal/chromehttp1` is not vendored. It is an HTTP/1.1 request writer and
connection pool written for this library, because `net/http` sorts header names.

See [update-deps/README.md](update-deps/README.md) and
[stand/README.md](stand/README.md).
