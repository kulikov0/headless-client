package headless

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kulikov0/headless-client/webrtc"
)

const chromeCnameAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func audioAndVideoOffer(t *testing.T) string {
	t.Helper()

	peerConnection := defaultCodecPeerConnection(t)

	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
	)
	if err != nil {
		t.Fatalf("new video track: %v", err)
	}
	if _, err = peerConnection.AddTrack(videoTrack); err != nil {
		t.Fatalf("add video track: %v", err)
	}

	audioTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
	)
	if err != nil {
		t.Fatalf("new audio track: %v", err)
	}
	if _, err = peerConnection.AddTrack(audioTrack); err != nil {
		t.Fatalf("add audio track: %v", err)
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	return offer.SDP
}

func cnameValues(t *testing.T, sessionDescription string) []string {
	t.Helper()

	values := []string{}
	for _, line := range strings.Split(sessionDescription, "\r\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "a=ssrc:") {
			continue
		}

		if value, found := strings.CutPrefix(fields[1], "cname:"); found {
			values = append(values, value)
		}
	}

	if len(values) == 0 {
		t.Fatalf("no a=ssrc cname line in the description")
	}

	return values
}

func TestCnameHasTheChromeShape(t *testing.T) {
	for _, value := range cnameValues(t, audioAndVideoOffer(t)) {
		if len(value) != 16 {
			t.Fatalf("cname %q is %d characters, chrome uses 16", value, len(value))
		}

		if strings.ContainsFunc(value, func(character rune) bool {
			return !strings.ContainsRune(chromeCnameAlphabet, character)
		}) {
			t.Fatalf("cname %q leaves the chrome base64 alphabet", value)
		}
	}
}

func TestCnameIsOnePerPeerConnection(t *testing.T) {
	sessionDescription := audioAndVideoOffer(t)

	values := cnameValues(t, sessionDescription)
	if len(values) < 2 {
		t.Fatalf("expected a cname in both the audio and the video section, got %d", len(values))
	}

	for _, value := range values[1:] {
		if value != values[0] {
			t.Fatalf("cname differs across sections: %q and %q", values[0], value)
		}
	}

	if strings.Contains(sessionDescription, "cname:tunnel") {
		t.Fatalf("the streamID still reaches the wire as a cname")
	}
}

func msidValues(t *testing.T, sessionDescription, attributePrefix string) []string {
	t.Helper()

	values := []string{}
	for _, line := range strings.Split(sessionDescription, "\r\n") {
		if value, found := strings.CutPrefix(line, attributePrefix); found {
			values = append(values, value)
		}
	}

	if len(values) == 0 {
		t.Fatalf("no %q line in the description", attributePrefix)
	}

	return values
}

func assertChromeMsid(t *testing.T, value string) {
	t.Helper()

	streamID, trackID, found := strings.Cut(value, " ")
	if !found {
		t.Fatalf("msid %q carries no track id", value)
	}

	if streamID != "-" {
		t.Fatalf("msid stream id is %q, chrome sends %q when the track has no stream", streamID, "-")
	}

	parsed, err := uuid.Parse(trackID)
	if err != nil {
		t.Fatalf("msid track id %q is not a uuid: %v", trackID, err)
	}

	if parsed.Version() != 4 {
		t.Fatalf("msid track id %q is uuid version %d, chrome generates version 4", trackID, parsed.Version())
	}

	if trackID != strings.ToLower(trackID) {
		t.Fatalf("msid track id %q is not lowercase", trackID)
	}
}

func TestMediaLevelMsidHasTheChromeShape(t *testing.T) {
	for _, value := range msidValues(t, audioAndVideoOffer(t), "a=msid:") {
		assertChromeMsid(t, value)
	}
}

func TestSsrcMsidHasTheChromeShape(t *testing.T) {
	sessionDescription := audioAndVideoOffer(t)

	for _, line := range strings.Split(sessionDescription, "\r\n") {
		_, attribute, found := strings.Cut(line, " ")
		if !found || !strings.HasPrefix(line, "a=ssrc:") {
			continue
		}

		if value, isMsid := strings.CutPrefix(attribute, "msid:"); isMsid {
			assertChromeMsid(t, value)
		}
	}

	if strings.Contains(sessionDescription, "tunnel") {
		t.Fatalf("the description still carries a caller supplied track name")
	}
}

func TestEmittedMsidMatchesTheTrackItCameFrom(t *testing.T) {
	peerConnection := defaultCodecPeerConnection(t)

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
	)
	if err != nil {
		t.Fatalf("new track: %v", err)
	}
	if _, err = peerConnection.AddTrack(track); err != nil {
		t.Fatalf("add track: %v", err)
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	expected := track.StreamID() + " " + track.ID()
	for _, value := range msidValues(t, offer.SDP, "a=msid:") {
		if value != expected {
			t.Fatalf("description carries msid %q while the track reports %q", value, expected)
		}
	}
}

func videoAnswer(t *testing.T, mungeOffer func(string) string) string {
	t.Helper()

	offerer := defaultCodecPeerConnection(t)
	answerer := defaultCodecPeerConnection(t)

	for _, peerConnection := range []*webrtc.PeerConnection{offerer, answerer} {
		track, err := webrtc.NewTrackLocalStaticSample(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		)
		if err != nil {
			t.Fatalf("new track: %v", err)
		}

		if peerConnection == answerer {
			offer, offerErr := offerer.CreateOffer(nil)
			if offerErr != nil {
				t.Fatalf("create offer: %v", offerErr)
			}

			if mungeOffer != nil {
				offer.SDP = mungeOffer(offer.SDP)
			}

			if err = answerer.SetRemoteDescription(offer); err != nil {
				t.Fatalf("set remote description: %v", err)
			}
		}

		if _, err = peerConnection.AddTrack(track); err != nil {
			t.Fatalf("add track: %v", err)
		}
	}

	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}

	if !strings.Contains(answer.SDP, "a=ssrc:") {
		t.Fatalf("answer carries no ssrc line, the sending track never attached")
	}

	return answer.SDP
}

func TestAnswerDropsTheSsrcMsidWhenTheOfferCarriedBothForms(t *testing.T) {
	answer := videoAnswer(t, nil)

	if strings.Contains(answer, " msid:") && !strings.Contains(answer, "a=msid:") {
		t.Fatalf("answer carries no media level msid at all")
	}

	for _, line := range strings.Split(answer, "\r\n") {
		if strings.HasPrefix(line, "a=ssrc:") && strings.Contains(line, " msid:") {
			t.Fatalf("answer still carries the plan b ssrc msid line: %q", line)
		}
	}

	if !strings.Contains(answer, "\r\na=msid:- ") {
		t.Fatalf("answer lost the media level msid line")
	}
}

func TestAnswerKeepsTheSsrcMsidForAPlanBOffer(t *testing.T) {
	stripMediaLevelMsid := func(offer string) string {
		lines := []string{}
		for _, line := range strings.Split(offer, "\r\n") {
			if !strings.HasPrefix(line, "a=msid:") {
				lines = append(lines, line)
			}
		}

		return strings.Join(lines, "\r\n")
	}

	answer := videoAnswer(t, stripMediaLevelMsid)

	if strings.Contains(answer, "\r\na=msid:") {
		t.Fatalf("answer carries a media level msid the plan b offerer cannot read")
	}

	if !strings.Contains(answer, " msid:- ") {
		t.Fatalf("answer carries no ssrc msid line for a plan b offerer")
	}
}

func TestMsidSemanticHasTheChromeShape(t *testing.T) {
	lines := msidValues(t, audioAndVideoOffer(t), "a=msid-semantic")

	if len(lines) != 1 {
		t.Fatalf("expected one msid-semantic line, got %d", len(lines))
	}

	if lines[0] != ": WMS" {
		t.Fatalf("msid-semantic value is %q, chrome sends %q", lines[0], ": WMS")
	}
}

func TestSsrcCarriesOnlyCnameAndMsid(t *testing.T) {
	sessionDescription := audioAndVideoOffer(t)

	attributesPerSSRC := map[string][]string{}
	for _, line := range strings.Split(sessionDescription, "\r\n") {
		value, found := strings.CutPrefix(line, "a=ssrc:")
		if !found {
			continue
		}

		ssrc, attribute, split := strings.Cut(value, " ")
		if !split {
			t.Fatalf("ssrc line carries no attribute: %q", line)
		}

		name, _, _ := strings.Cut(attribute, ":")
		attributesPerSSRC[ssrc] = append(attributesPerSSRC[ssrc], name)
	}

	if len(attributesPerSSRC) == 0 {
		t.Fatalf("no a=ssrc line in the description")
	}

	for ssrc, names := range attributesPerSSRC {
		if len(names) != 2 || names[0] != "cname" || names[1] != "msid" {
			t.Fatalf("ssrc %s carries %v, chrome sends cname then msid", ssrc, names)
		}
	}
}

func TestTwoPeerConnectionsPickDifferentCnames(t *testing.T) {
	first := cnameValues(t, audioAndVideoOffer(t))[0]
	second := cnameValues(t, audioAndVideoOffer(t))[0]

	if first == second {
		t.Fatalf("both peer connections picked the cname %q", first)
	}
}
