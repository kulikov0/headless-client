# update-deps

Scripts that regenerate the vendored packages in this module. A vendored
package is a copy of a third-party module with its import paths rewritten to a
path inside this module.

Do not edit internal/dtls, internal/ice, internal/chromehttp2, quic, webrtc, or
websocket by hand. Run the scripts.

internal/chromehttp1 is not vendored. Edit it directly. See
"internal/chromehttp1".

## Packages

- internal/dtls: a fork of github.com/pion/dtls/v3 with DTLS 1.3.
- internal/ice: github.com/pion/ice/v4 with the keepalive interval patch.
- webrtc: github.com/pion/webrtc/v4 with its dtls and ice imports pointed at
  internal/dtls and internal/ice, and the RTP header extension and SDP patches.
  It is at the top level because consumers import it.
- internal/chromehttp2: the http2, internal/httpcommon, and internal/httpsfv
  packages of golang.org/x/net, with the HTTP/2 fingerprint patch.
- websocket: github.com/gorilla/websocket with the Chrome handshake patch. It is
  at the top level because consumers import it.
- quic: github.com/sardanioss/quic-go and github.com/sardanioss/qpack, pointed at
  refraction-networking/utls and net/http. It is at the top level because
  consumers import quic, http3 and quicvarint directly.

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
5. Apply dtls-default-version.patch, dtls-handshake-fragment-mtu.patch and
   dtls-serverhello13-hook.patch.
6. Build internal/dtls.

Changes this module makes on top of upstream are stored in update-deps as patch
files. The vendored source tree holds no hand edits.

Patch application is idempotent. If a patch is already applied in the source,
the script skips it instead of failing. A source with the local change and a
source without it produce the same result.

To move to a newer upstream commit, change COMMIT in the script and run it.

## ice.sh

    ./update-deps/ice.sh [version]

Default version: v4.2.2.

Steps:

1. Download the module and copy it to internal/ice.
2. Remove .git at any depth, .github, go.mod, go.sum, tests, testdata,
   examples, e2e, README.md, codecov.yml, and renovate.json.
3. Rewrite github.com/pion/ice/v4 to the internal path.
4. Apply ice-keepalive-interval.patch.
5. Build internal/ice.

## webrtc.sh

    ./update-deps/webrtc.sh [version]

Default version: v4.2.11.

Run dtls.sh and ice.sh first. The build step of this script compiles webrtc,
which imports internal/dtls and internal/ice.

Steps:

1. Download the module and copy it to webrtc.
2. Remove .git at any depth, .github, go.mod, go.sum, tests, testdata,
   examples, e2e, README.md, codecov.yml, and renovate.json.
3. Rewrite github.com/pion/webrtc/v4 to the webrtc path,
   github.com/pion/dtls/v3 to internal/dtls, and github.com/pion/ice/v4 to
   internal/ice.
4. Run gofmt.
5. Apply the webrtc-*.patch files in the order listed in the script.
6. Build webrtc.

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

## chromequic.sh

    ./update-deps/chromequic.sh [version] [qpack-version]

Default versions: v1.2.28 and v0.6.3.

Steps:

1. Download github.com/sardanioss/quic-go and copy it to quic. Copy
   github.com/sardanioss/qpack to quic/qpack. Non-test files only.
2. Remove upstream tooling, tests and mocks. The full list is in the script.
3. Rewrite github.com/sardanioss/quic-go to the quic path,
   github.com/sardanioss/qpack to quic/qpack, github.com/sardanioss/utls to
   github.com/refraction-networking/utls, and github.com/sardanioss/http to
   net/http. The two header-order keys of that http fork become local constants.
4. Copy the files from _chromequic-files.
5. Apply the chromequic-*.patch files in the order listed in the script.
6. Build quic. The script does not test, run `go test ./quic/...` after it.

The qpack fork is copied rather than replaced with github.com/quic-go/qpack
because it adds a Sensitive field to HeaderField and the never-index encoding
that goes with it. Upstream qpack has neither, so http3 does not compile
against it.

The upstream is a fork of quic-go that matches Chrome's QUIC fingerprint. Its
own uTLS is a fork of refraction-networking/utls. Every uTLS symbol the QUIC
code needs exists in refraction v1.8.2 except three additions,
UQUICConn.StoreSession, ClientHelloSpec.GREASESeed and UQUICConn.GetGREASESeed,
which chromequic-refraction-utls.patch removes.

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

## chromequic-refraction-utls.patch

Changes quic/internal/handshake/crypto_setup.go and three files under
quic/http3. Applied by chromequic.sh.

The upstream fork uses three uTLS additions that refraction-networking/utls
v1.8.2 does not have. StoreSession becomes a no-op, so a QUIC session ticket is
not stored and a later connection runs a full handshake. The GREASE seed is no
longer carried across connections, so every connection draws its own GREASE
values, which is what a browser does anyway when the session is new.

The http3 files convert a utls.ConnectionState to a crypto/tls.ConnectionState
before handing it to net/http and net/http/httptrace, which are typed against
crypto/tls. The converter is tls_state.go from _chromequic-files.

## chromequic-preset-transport-params.patch

Changes uquicWrapper in quic/internal/handshake/crypto_setup.go. Applied by
chromequic.sh.

refraction-networking/utls marshals its QUICTransportParametersExtension from a
structured TransportParameters value and its SetTransportParameters explicitly
does not write into a preset, so a ClientHelloSpec built by hand emits
quic_transport_parameters with length zero. The patch gives the wrapper a
reference to the spec and fills the raw bytes into the utls.GenericExtension
that carries extension 57. ApplyPreset copies extension pointers and does not
marshal the ClientHello, so the value set here reaches the wire.

Without the patch the handshake still completes against some servers, but JA4
reports the connection as t rather than q, because the transport parameters
extension is empty. That difference only shows on the wire, so the check is a
stand capture rather than a unit test.

## chromequic-chaos-protection.patch

Replaces the fork's ChromeStyleInitialPackets with Chrome's chaos protector:
client Initial CRYPTO frames are split, reordered and mixed with PING and
PADDING. Guards in quic/chaos_protector_test.go.

## chromequic-http3-settings.patch

Writes SETTINGS in ascending identifier order with one GREASE setting, and
skips PRIORITY_UPDATE on extended CONNECT. Guards in
quic/http3/http3_settings_test.go.

## chromequic-webtransport-connect.patch

Lets a nil User-Agent suppress the default one, as Chrome's WebTransport
CONNECT carries none. Guards in quic/http3/webtransport_connect_test.go.

## websocket-chrome-handshake.patch

Changes websocket/client.go in two places. The upgrade request is written with
chromehttp1.WriteRequest instead of req.Write, so the request uses Chrome's
header order. Sec-Websocket-Extensions is removed from the forbidden-header
list, so a caller can set Chrome's permessage-deflate parameters. Applied by
websocket.sh.

The guards are TestVendoredWebSocketWritesTheChromeHeaderOrder and
TestVendoredWebSocketCarriesTheProfileExtensions in websocket_vendor_test.go.
They dial a local listener, read the upgrade request off the socket, and check
the header order against pairs that alphabetical order would swap.

## dtls-default-version.patch

Changes NormalizeProtocolVersionRange in internal/dtls. An unset maximum
version becomes DTLS 1.3 instead of DTLS 1.2, so the ClientHello offers both
versions the way a browser does. Applied by dtls.sh.

The guard is TestVendoredDTLSOffersBothProtocolVersions in dtls_vendor_test.go.
It runs a loopback handshake and reads supported_versions off the ClientHello.

## dtls-handshake-fragment-mtu.patch

Changes prepareHandshakeRecords and fragmentHandshake in internal/dtls/conn.go.
Applied by dtls.sh.

Upstream splits a handshake message into fragments of the full MTU and then
adds the handshake fragment header and the record header on top, so a handshake
datagram is larger than the configured MTU. Chrome sizes the first fragment so
that the datagram is exactly the MTU. The patch subtracts the record overhead
and the handshake header before it splits. The record overhead is the fixed
record header, or, for a protected DTLS 1.3 record, the unified header with the
active connection ID plus the AEAD expansion of the cipher suite.

The guard is TestVendoredDTLSFillsTheHandshakeDatagramToTheMTU in
dtls_vendor_test.go. It runs a loopback handshake against an MTU of 200 bytes
and checks that no client datagram is over the MTU and that one datagram
reaches it.

## dtls-serverhello13-hook.patch

Changes flight4Generate in
internal/dtls/internal/flight/flight13/flight4handler.go. Applied by dtls.sh.

Upstream calls ServerHelloMessageHook on the DTLS 1.2 path only, through
dtlsflight.FinalizeServerHello. That helper cannot be reused here, because
negotiation.ValidateServerHello12Context, which it calls, rejects any response
carrying supported_versions, key_share or pre_shared_key, which is every 1.3
server hello. Without the patch a 1.3 server hello ships pion's extension order
and the profile hook never runs.

The patch adds finalizeServerHello13. The hook may reorder the extensions and
nothing else: the extension types before and after the hook must match, which
is what the Chrome order needs and all it needs. A hooked connection ID is
checked with the upstream dtlsflight.ValidateHookedConnectionIDLength, the same
call the 1.2 path makes. The connection ID decision is taken from the hooked
extensions rather than the ones built before the hook, so the session records
the connection ID that goes on the wire.

The guards are in dtls_vendor_test.go.
TestVendoredDTLSCallsTheServerHelloHookOnVersion13 checks that the hook runs on
a 1.3 handshake, TestVendoredDTLSServerHelloCarriesTheChromeOrderOnVersion13
checks the emitted order, and
TestVendoredDTLSRejectsAServerHelloHookThatLeavesTheExtensionSet checks that a
hook which drops or resizes the connection ID fails the handshake.

## ice-keepalive-interval.patch

Changes the task loop in internal/ice/agent.go. Upstream passes the keepalive
interval to updateInterval, which only lowers the loop tick. The loop starts at
the 2 s package default, so a keepalive above 2 s is discarded and
SetICETimeouts does not change the ping cadence. The patch assigns the interval
directly in the connected and disconnected cases.

Applied by ice.sh. The guard is TestVendoredICEKeepsTheKeepaliveIntervalPatch in
ice_test.go. It reads the vendored source, because ice.sh deletes every test
file in internal/ice.

## chromehttp2-fingerprint.patch

Changes internal/chromehttp2/transport.go, which controls the SETTINGS frame
and the connection window update, and internal/httpcommon/request.go, which
controls pseudo-header order, content-length position, and chromeHeaderOrder.
Applied by chromehttp2.sh.

## webrtc-header-extension-order.patch

Changes getRTPParametersByKind in webrtc/mediaengine.go and adds a field to
MediaEngine that holds the identifier picker. Applied by webrtc.sh.

Upstream collects the offered header extensions in a map and then ranges over
it, so the a=extmap lines come out in a different order in every offer. It also
allocates identifiers by scanning up from 1. libwebrtc walks a fixed list and
allocates from the top of the one byte range downwards, so its offers are
identical every time and its identifiers differ from ours. The patch changes
both. The lines are emitted in the order of the list in internal/rtpext, and the
identifiers come from rtpext.Picker.

The tables in internal/rtpext come from media/engine/webrtc_video_engine.cc and
media/engine/webrtc_voice_engine.cc in webrtc. The allocation rule comes from
RtpHeaderExtensionPicker::SuggestMapping in call/payload_type_picker.cc. A URI
that was already given an identifier keeps it in every later media section, an
unused preferred identifier is taken as is, and anything else is allocated from
the top of the one byte range downwards.

The patch is applied after gofmt. The import rewrite in step 3 moves one import
line and gofmt moves it back. A patch generated from the formatted tree does not
apply to the unformatted tree.

The guards are TestOfferCarriesTheChromeHeaderExtensionOrderAndIDs and
TestTwoOffersCarryTheSameHeaderExtensionOrder in rtpext_vendor_test.go. The
first builds an offer through the public API and compares the extmap lines of
both media sections against a browser capture. Removing the sort call changes
the order of the video section. Reversing the direction of the picker scan gives
toffset the identifier 5 instead of 14.

## webrtc-answer-codec-order.patch

Emits answer codecs in the offer's payload type order. Guard:
TestAnswerKeepsThePayloadTypeOrderOfTheOffer.

## webrtc-rtcp-cname.patch

Uses one random 16 character cname per peer connection instead of the stream
ID. Guard: TestCnameIsOnePerPeerConnection.

## webrtc-msid-track-identity.patch

Gives local tracks a UUIDv4 track ID and the stream ID `-`. Guard:
TestMediaLevelMsidHasTheChromeShape.

## webrtc-ssrc-attributes.patch

Emits only `cname` and `msid` on a=ssrc lines, no `mslabel` or `label`. Guard:
TestSsrcCarriesOnlyCnameAndMsid.

## webrtc-msid-semantic.patch

Writes `a=msid-semantic: WMS` instead of `WMS *`. Guard:
TestMsidSemanticHasTheChromeShape.

## webrtc-answer-msid-signaling.patch

Answers with the msid form the offer used: a=ssrc msid only for a Plan B
offer, media level a=msid otherwise. Guard:
TestAnswerDropsTheSsrcMsidWhenTheOfferCarriedBothForms.

## webrtc-track-constructor-args.patch

Removes the id and streamID arguments from NewTrackLocalStaticRTP and
NewTrackLocalStaticSample, since the identity patch ignores them. This changes
the public API.

## webrtc-session-origin.patch

Sets the o= session version to 2 and the address to 127.0.0.1, as Chrome does.
Guard: TestVendoredWebRTCSeedsTheSessionOriginLikeChrome.

## webrtc-codec-feedback.patch

Gives transport-cc to Opus and to video codecs in Chrome's order, and writes
a=fmtp after a=rtcp-fb. Guards in sdpcodec_vendor_test.go.

## webrtc-answer-feedback-order.patch

Answers with the local feedback list filtered by the offer. Guard:
TestVendoredWebRTCAnswersWithTheLocalFeedbackOrder.

## webrtc-attribute-order.patch

Reorders session and media attributes by the tables in internal/sdporder, and
adds Chrome's a=rtcp and a=ice-options lines. Guards in
sdpsectionorder_vendor_test.go.

## _chromequic-files

Copied into quic by chromequic.sh.

- header_order_keys.go: the two header-order keys that the
  github.com/sardanioss/http fork exports and net/http does not.
- tls_state.go: converts between the two ConnectionState types.
- chaos_protector.go: the frame scattering called by
  chromequic-chaos-protection.patch.
- chaos_protector_test.go, http3_settings_test.go,
  webtransport_connect_test.go: guards for the matching patches.

The underscore prefix stops the go tool from building the directory.

## _dtls-files

compat_shim.go, copied into internal/dtls by dtls.sh.

The vendored trees are pinned to different points of the pion history.
internal/dtls comes from pion/dtls main. webrtc and internal/ice come from
pion/webrtc v4.2.11 and pion/ice v4.2.2, which are built against the pion/dtls
v3.1.2 release. Neither of those two trees is patched here, so their calls into
dtls are upstream code.

Four names differ between the release and main. The release has
ClientWithOptions, ServerWithOptions, CipherSuiteID and CipherSuite in the root
package. On main the constructors are Client and Server, and the two types are
in pkg/crypto/ciphersuite. The shim declares the four release names, so the
vendored trees compile against internal/dtls without changes.

The alternative is a patch per call site in webrtc/dtlstransport.go,
webrtc/settingengine.go and internal/ice/gather.go, re-derived on every webrtc
and ice update.

Remove the shim once a pion/dtls release carries the main API and webrtc and ice
are updated to it.

The underscore prefix stops the go tool from building the directory.

## _chromehttp2-tests

chrome_fingerprint_test.go and httpcommon/header_order_test.go, copied into
internal/chromehttp2 by chromehttp2.sh.

The underscore prefix stops the go tool from building the directory.

## Dependency versions

The scripts regenerate source. Module versions are in go.mod. If a new upstream
version needs a newer dependency, the build fails with an undefined symbol. Run
go get for that dependency, then run the script again.

webrtc v4.2.11 needs github.com/pion/sctp v1.9.4 and ice v4.2.2. ice is
vendored, so its version does not appear in go.mod. The version lives in the
VERSION variable of ice.sh.
