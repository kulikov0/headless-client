package headless

import (
	"slices"
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

var chromeAudioExtmapLines = []string{
	"1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
	"2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
	"3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	"4 urn:ietf:params:rtp-hdrext:sdes:mid",
}

var chromeVideoExtmapLines = []string{
	"14 urn:ietf:params:rtp-hdrext:toffset",
	"2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
	"13 urn:3gpp:video-orientation",
	"3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	"5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
	"6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
	"7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
	"8 http://www.webrtc.org/experiments/rtp-hdrext/color-space",
	"4 urn:ietf:params:rtp-hdrext:sdes:mid",
	"10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
	"11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	"12 https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension",
	"9 http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00",
}

func chromeShapedPeerConnection(t *testing.T) *webrtc.PeerConnection {
	t.Helper()

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("register default codecs: %v", err)
	}
	if err := ChromeWindows.RegisterHeaderExtensions(mediaEngine); err != nil {
		t.Fatalf("register header extensions: %v", err)
	}

	api := webrtc.NewAPI(webrtc.WithMediaEngine(mediaEngine))
	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	t.Cleanup(func() { _ = peerConnection.Close() })

	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatalf("add audio transceiver: %v", err)
	}
	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("add video transceiver: %v", err)
	}

	return peerConnection
}

func chromeShapedOffer(t *testing.T) (audioLines, videoLines []string) {
	t.Helper()

	offer, err := chromeShapedPeerConnection(t).CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	return extmapLinesPerSection(offer.SDP)
}

type mediaSection struct {
	kind  string
	lines []string
}

func extmapSections(sdp string) []mediaSection {
	sections := make([]mediaSection, 0, 3)
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "m="):
			kind, _, _ := strings.Cut(strings.TrimPrefix(line, "m="), " ")
			sections = append(sections, mediaSection{kind: kind})
		case strings.HasPrefix(line, "a=extmap:") && len(sections) > 0:
			current := &sections[len(sections)-1]
			current.lines = append(current.lines, strings.TrimPrefix(line, "a=extmap:"))
		}
	}

	return sections
}

func extmapLinesPerSection(sdp string) (audioLines, videoLines []string) {
	for _, section := range extmapSections(sdp) {
		if section.kind == "video" {
			videoLines = append(videoLines, section.lines...)
		} else {
			audioLines = append(audioLines, section.lines...)
		}
	}

	return audioLines, videoLines
}

func TestOfferCarriesTheChromeHeaderExtensionOrderAndIDs(t *testing.T) {
	audioLines, videoLines := chromeShapedOffer(t)

	if !slices.Equal(audioLines, chromeAudioExtmapLines) {
		t.Fatalf("audio extmap is\n  %s\nchrome sends\n  %s",
			strings.Join(audioLines, "\n  "), strings.Join(chromeAudioExtmapLines, "\n  "))
	}
	if !slices.Equal(videoLines, chromeVideoExtmapLines) {
		t.Fatalf("video extmap is\n  %s\nchrome sends\n  %s",
			strings.Join(videoLines, "\n  "), strings.Join(chromeVideoExtmapLines, "\n  "))
	}
}

func TestTwoOffersCarryTheSameHeaderExtensionOrder(t *testing.T) {
	for attempt := range 8 {
		firstAudio, firstVideo := chromeShapedOffer(t)
		secondAudio, secondVideo := chromeShapedOffer(t)

		if !slices.Equal(firstAudio, secondAudio) {
			t.Fatalf("attempt %d audio extmap differs between offers\n  %s\n  %s",
				attempt, strings.Join(firstAudio, " | "), strings.Join(secondAudio, " | "))
		}
		if !slices.Equal(firstVideo, secondVideo) {
			t.Fatalf("attempt %d video extmap differs between offers\n  %s\n  %s",
				attempt, strings.Join(firstVideo, " | "), strings.Join(secondVideo, " | "))
		}
	}
}

func TestRenegotiationReusesTheHeaderExtensionIDs(t *testing.T) {
	peerConnection := chromeShapedPeerConnection(t)

	first, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create first offer: %v", err)
	}
	if err = peerConnection.SetLocalDescription(first); err != nil {
		t.Fatalf("set local description: %v", err)
	}
	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("add second video transceiver: %v", err)
	}

	second, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create second offer: %v", err)
	}

	sections := extmapSections(second.SDP)
	if len(sections) != 3 {
		t.Fatalf("the renegotiated offer has %d media sections, want 3", len(sections))
	}
	if !slices.Equal(sections[1].lines, chromeVideoExtmapLines) {
		t.Fatalf("the first video section is\n  %s\nwant\n  %s",
			strings.Join(sections[1].lines, "\n  "), strings.Join(chromeVideoExtmapLines, "\n  "))
	}
	if !slices.Equal(sections[2].lines, sections[1].lines) {
		t.Fatalf("the added video section is\n  %s\nthe first one is\n  %s",
			strings.Join(sections[2].lines, "\n  "), strings.Join(sections[1].lines, "\n  "))
	}
}
