package headless

import (
	"regexp"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

var sdpOriginLine = regexp.MustCompile(`(?m)^o=\S+ \S+ (\S+) IN IP4 (\S+)`)

func TestVendoredWebRTCSeedsTheSessionOriginLikeChrome(t *testing.T) {
	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}
	peerConnection, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer peerConnection.Close() //nolint:errcheck

	if _, err = peerConnection.CreateDataChannel("probe", nil); err != nil {
		t.Fatalf("create data channel: %v", err)
	}

	for offerIndex, wantVersion := range []string{"2", "3"} {
		offer, err := peerConnection.CreateOffer(nil)
		if err != nil {
			t.Fatalf("create offer %d: %v", offerIndex, err)
		}
		match := sdpOriginLine.FindStringSubmatch(offer.SDP)
		if match == nil {
			t.Fatalf("offer %d has no o= line", offerIndex)
		}
		version, address := match[1], match[2]
		if version != wantVersion {
			t.Fatalf("offer %d has session version %s, chrome seeds kInitSessionVersion 2 and increments per created local description, upstream pion seeds a unix timestamp that leaks wall clock time in a field the backend reads",
				offerIndex, version)
		}
		if address != "127.0.0.1" {
			t.Fatalf("offer %d has origin address %s, chrome writes kSessionOriginAddress 127.0.0.1 and upstream pion writes 0.0.0.0",
				offerIndex, address)
		}
	}
}
