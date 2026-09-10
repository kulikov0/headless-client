package headless

import (
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

func defaultCodecPeerConnection(t *testing.T) *webrtc.PeerConnection {
	t.Helper()

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("register default codecs: %v", err)
	}

	api := webrtc.NewAPI(webrtc.WithMediaEngine(mediaEngine))
	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	t.Cleanup(func() { _ = peerConnection.Close() })

	return peerConnection
}

func payloadTypesPerSection(t *testing.T, sessionDescription, mediaKind string) [][]string {
	t.Helper()

	sections := [][]string{}
	for _, line := range strings.Split(sessionDescription, "\r\n") {
		if !strings.HasPrefix(line, "m="+mediaKind+" ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			t.Fatalf("media line carries no payload types: %q", line)
		}

		sections = append(sections, fields[3:])
	}

	if len(sections) == 0 {
		t.Fatalf("no %s section in the description", mediaKind)
	}

	return sections
}

func twoSectionOfferAndAnswer(t *testing.T) (offered, answered [][]string) {
	t.Helper()

	offerer := defaultCodecPeerConnection(t)
	answerer := defaultCodecPeerConnection(t)

	for sectionCount := 0; sectionCount < 2; sectionCount++ {
		if _, err := offerer.AddTransceiverFromKind(
			webrtc.RTPCodecTypeVideo,
			webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly},
		); err != nil {
			t.Fatalf("add video transceiver: %v", err)
		}
	}

	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	if err = answerer.SetRemoteDescription(offer); err != nil {
		t.Fatalf("set remote description: %v", err)
	}

	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}

	return payloadTypesPerSection(t, offer.SDP, "video"),
		payloadTypesPerSection(t, answer.SDP, "video")
}

func TestAnswerKeepsThePayloadTypeOrderOfTheOffer(t *testing.T) {
	offered, answered := twoSectionOfferAndAnswer(t)

	if len(answered) != len(offered) {
		t.Fatalf("the answer carries %d video sections, the offer carries %d", len(answered), len(offered))
	}

	for section := range answered {
		got := strings.Join(answered[section], " ")
		want := strings.Join(offered[section], " ")
		if got != want {
			t.Errorf("video section %d answers %q, chrome keeps the offer order %q", section, got, want)
		}
	}
}

func TestTwoIdenticalSectionsAnswerWithOneOrder(t *testing.T) {
	_, answered := twoSectionOfferAndAnswer(t)

	if len(answered) < 2 {
		t.Fatalf("the answer carries %d video sections, the guard needs two", len(answered))
	}

	first := strings.Join(answered[0], " ")
	for section := 1; section < len(answered); section++ {
		if other := strings.Join(answered[section], " "); other != first {
			t.Errorf(
				"video section %d answers %q while section 0 answers %q, one description must not carry two orders",
				section, other, first,
			)
		}
	}
}
