package headless

import (
	"slices"
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/internal/sdporder"
	"github.com/kulikov0/headless-client/webrtc"
)

func TestVendoredWebRTCOrdersTheSessionAttributesLikeChrome(t *testing.T) {
	want := []string{"group", "extmap-allow-mixed", "msid-semantic"}

	got := sessionAttributeNames(t, offerFromDefaultProfile(t))
	if !slices.Equal(got, want) {
		t.Fatalf("session attributes are %v, chrome writes %v, see SdpSerialize in api/webrtc_sdp.cc which emits group, extmap-allow-mixed, cryptex, msid-semantic, ice-lite in that fixed order",
			got, want)
	}
}

func TestVendoredWebRTCOrdersTheRTPSectionLikeChrome(t *testing.T) {
	want := []string{
		"rtcp", "ice-ufrag", "ice-pwd", "ice-options", "fingerprint", "setup", "mid",
		"extmap", "sendrecv", "rtcp-mux", "rtcp-rsize", "rtpmap",
	}

	sections := sectionAttributeNames(t, offerFromDefaultProfile(t))
	for kind, names := range sections {
		if kind == "application" {
			continue
		}
		if got := firstOccurrences(names, want); !slices.Equal(got, want) {
			t.Fatalf("m=%s attribute order is %v,\nchrome is %v,\nsee BuildMediaDescription and BuildRtpContentAttributes in api/webrtc_sdp.cc",
				kind, got, want)
		}
	}
}

func TestVendoredWebRTCOrdersTheDataSectionLikeChrome(t *testing.T) {
	want := []string{"ice-ufrag", "ice-pwd", "ice-options", "fingerprint", "setup", "mid", "sctp-port", "max-message-size"}

	names := sectionAttributeNames(t, offerFromDefaultProfile(t))["application"]
	if names == nil {
		t.Fatal("offer carries no data section")
	}
	if !slices.Equal(names, want) {
		t.Fatalf("m=application attribute order is %v, chrome is %v, and BuildSctpContentAttributes writes no direction line at all",
			names, want)
	}
}

func TestVendoredWebRTCCapsTheSCTPMaxMessageSizeLikeChrome(t *testing.T) {
	const chromeSendBufferSize = "262144"

	for _, line := range strings.Split(offerFromDefaultProfile(t), "\n") {
		line = strings.TrimSpace(line)
		value, found := strings.CutPrefix(line, "a=max-message-size:")
		if !found {
			continue
		}
		if value != chromeSendBufferSize {
			t.Fatalf("a=max-message-size is %s, chrome caps it at kSctpSendBufferSize %s, api/sctp_transport_interface.h, and pion echoes whatever it was handed",
				value, chromeSendBufferSize)
		}

		return
	}
	t.Fatal("offer carries no a=max-message-size")
}

func TestVendoredWebRTCEmitsNoAttributeOutsideTheChromeOrder(t *testing.T) {
	offer := offerFromDefaultProfile(t)

	if missing := sdporder.Unknown(sdporder.LevelSession, sessionAttributeNames(t, offer)); len(missing) != 0 {
		t.Fatalf("session attributes %v have no rank, they would sort to the end of the session block; add them to sdporder or stop emitting them", missing)
	}
	for kind, names := range sectionAttributeNames(t, offer) {
		if missing := sdporder.Unknown(sdporder.LevelMedia, names); len(missing) != 0 {
			t.Fatalf("m=%s attributes %v have no rank, they would sort to the end of the section; add them to sdporder or stop emitting them", kind, missing)
		}
	}
}

func offerFromDefaultProfile(t *testing.T) string {
	t.Helper()

	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}
	peerConnection, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer peerConnection.Close() //nolint:errcheck

	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatalf("add audio transceiver: %v", err)
	}
	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("add video transceiver: %v", err)
	}
	if _, err = peerConnection.CreateDataChannel("probe", nil); err != nil {
		t.Fatalf("create data channel: %v", err)
	}
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	return offer.SDP
}

func sessionAttributeNames(t *testing.T, offer string) []string {
	t.Helper()

	names := []string{}
	for _, line := range strings.Split(offer, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "m=") {
			break
		}
		if attribute, found := strings.CutPrefix(line, "a="); found {
			names = append(names, sdporder.AttributeName(attribute))
		}
	}

	return names
}

func sectionAttributeNames(t *testing.T, offer string) map[string][]string {
	t.Helper()

	sections := map[string][]string{}
	kind := ""
	for _, line := range strings.Split(offer, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "m=") {
			kind = strings.TrimPrefix(strings.Fields(line)[0], "m=")
			sections[kind] = []string{}

			continue
		}
		attribute, found := strings.CutPrefix(line, "a=")
		if !found || kind == "" {
			continue
		}
		sections[kind] = append(sections[kind], sdporder.AttributeName(attribute))
	}

	return sections
}

func firstOccurrences(names, wanted []string) []string {
	seen := []string{}
	for _, name := range names {
		if slices.Contains(wanted, name) && !slices.Contains(seen, name) {
			seen = append(seen, name)
		}
	}

	return seen
}
