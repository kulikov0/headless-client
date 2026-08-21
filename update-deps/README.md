# update-deps

Scripts that regenerate the vendored packages in this module. A vendored
package is a copy of a third-party module with its import paths rewritten to a
path inside this module.

Do not edit internal/dtls, internal/chromehttp2, webrtc, or websocket by hand.
Run the scripts.

internal/chromehttp1 is not vendored. Edit it directly. See
"internal/chromehttp1".

## Packages

- internal/dtls: a fork of github.com/pion/dtls/v3 with DTLS 1.3.
- webrtc: github.com/pion/webrtc/v4 with its dtls import pointed at
  internal/dtls. No other change. It is at the top level because consumers
  import it.
- internal/chromehttp2: the http2, internal/httpcommon, and internal/httpsfv
  packages of golang.org/x/net, with the HTTP/2 fingerprint patch.
- websocket: github.com/gorilla/websocket with the Chrome handshake patch. It is
  at the top level because consumers import it.

## dtls.sh

    ./update-deps/dtls.sh [path-to-dtls-checkout]

The upstream commit is pinned in the COMMIT variable of the script. DTLS 1.3 is
not released, so there is no module version to download and the source is a git
checkout instead.

Without an argument, the script fetches the pinned commit into a temporary
directory and removes it when it exits. It does not need a local checkout.

With an argument, the script uses that checkout. It prints a warning if the
checkout is not at the pinned commit. Use this while developing against a local
dtls tree.

Both modes produce the same tree.

Steps:

1. Copy the source to internal/dtls.
2. Remove .git at any depth, .github, go.mod, go.sum, tests, testdata,
   examples, e2e, README.md, codecov.yml, and renovate.json.
3. Rewrite github.com/pion/dtls/v3 to the internal path.
4. Copy the files from _dtls-files.
5. Apply dtls-default-version.patch and dtls-dualstack-server-prime.patch.
6. Build internal/dtls.

Changes this module makes on top of upstream are stored in update-deps, not in
the source tree.

Patch application is idempotent. If a patch is already applied in the source,
the script skips it instead of failing. A source with the local change and a
source without it produce the same result.

To move to a newer upstream commit, change COMMIT in the script and run it.

## webrtc.sh

    ./update-deps/webrtc.sh [version]

Default version: v4.2.11.

Run dtls.sh first. The build step of this script compiles webrtc, which imports
internal/dtls.

Steps:

1. Download the module and copy it to webrtc.
2. Remove .git at any depth, .github, go.mod, go.sum, tests, testdata,
   examples, e2e, README.md, codecov.yml, and renovate.json.
3. Rewrite github.com/pion/webrtc/v4 to the webrtc path and
   github.com/pion/dtls/v3 to internal/dtls.
4. Build webrtc.

## chromehttp2.sh

    ./update-deps/chromehttp2.sh [version]

Default version: v0.55.0.

Steps:

1. Download golang.org/x/net and copy the http2, internal/httpcommon, and
   internal/httpsfv packages to internal/chromehttp2. Non-test files only.
2. Copy LICENSE and PATENTS.
3. Rewrite the golang.org/x/net/internal import paths to the internal path.
4. Remove the canonical import comment from http2.go.
5. Apply chromehttp2-fingerprint.patch.
6. Copy the tests from _chromehttp2-tests.
7. Build and test internal/chromehttp2.

## websocket.sh

    ./update-deps/websocket.sh [version]

Default version: v1.5.3.

Steps:

1. Download the module and copy it to websocket.
2. Remove .git at any depth, .github, .circleci, go.mod, go.sum, tests,
   testdata, examples, e2e, README.md, codecov.yml, renovate.json,
   .golangci.yml, and .gitignore.
3. Rewrite github.com/gorilla/websocket to the websocket path.
4. Apply websocket-chrome-handshake.patch.
5. Build websocket.

## internal/chromehttp1

This package is not vendored. It has no upstream and no script. Edit it
directly.

The package writes HTTP/1.1 requests in Chrome's header order. net/http sorts
headers alphabetically, which identifies the client as a Go program.

To update the package, re-measure Chrome. The chromeHTTP1HeaderOrder constant
comes from a browser packet capture. When Chrome changes its header order, take
a new capture, extract the order, and update the constant and the tests in
request_test.go.

websocket-chrome-handshake.patch calls chromehttp1.WriteRequest. If you change
that signature, the patched websocket tree does not compile. websocket.sh builds
websocket as its last step, so the failure appears when you run the script.

## websocket-chrome-handshake.patch

Changes websocket/client.go in two places. The upgrade request is written with
chromehttp1.WriteRequest instead of req.Write, so the request uses Chrome's
header order. Sec-Websocket-Extensions is removed from the forbidden-header
list, so a caller can set Chrome's permessage-deflate parameters. Applied by
websocket.sh.

## dtls-default-version.patch

Changes NormalizeProtocolVersionRange in internal/dtls. An unset maximum
version becomes DTLS 1.3 instead of DTLS 1.2. Applied by dtls.sh.

## dtls-dualstack-server-prime.patch

Changes prepareDualStackServerHandshakeStart in internal/dtls/conn.go.

Upstream calls primeHandshakeRecv on the dual-stack client path but not on the
dual-stack server path. Without the call, the server blocks until its
retransmit timer fires, and a handshake between two dual-stack peers fails with
a context deadline. The patch adds the same postSetup call that upstream
already uses for the client.

Applied by dtls.sh. Not in upstream as of pion/dtls commit 1211026.

## chromehttp2-fingerprint.patch

Changes internal/chromehttp2/transport.go, which controls the SETTINGS frame
and the connection window update, and internal/httpcommon/request.go, which
controls pseudo-header order, content-length position, and chromeHeaderOrder.
Applied by chromehttp2.sh.

## _dtls-files

compat_shim.go, copied into internal/dtls by dtls.sh. It restores the Config
struct and the Client and Server constructors that upstream removed, and maps
them onto ClientOption and ServerOption. The vendored tree does not build
without it.

The underscore prefix stops the go tool from building the directory.

## _chromehttp2-tests

chrome_fingerprint_test.go and httpcommon/header_order_test.go, copied into
internal/chromehttp2 by chromehttp2.sh.

The underscore prefix stops the go tool from building the directory.

## Dependency versions

The scripts regenerate source. Module versions are in go.mod. If a new upstream
version needs a newer dependency, the build fails with an undefined symbol. Run
go get for that dependency, then run the script again.

webrtc v4.2.11 needs github.com/pion/ice/v4 v4.2.2 and github.com/pion/sctp
v1.9.4.
