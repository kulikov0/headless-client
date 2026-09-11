package headless

import (
	"slices"
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

func TestVendoredWebRTCAnswersWithTheLocalFeedbackOrder(t *testing.T) {
	remoteFeedback := []string{"nack", "nack pli", "goog-remb"}
	wantAnswerFeedback := []string{"goog-remb", "nack", "nack pli"}

	answer := answerToOfferWithFeedback(t, remoteFeedback)

	found := false
	for _, block := range answer["video"] {
		if !strings.HasPrefix(block.name, "VP8/") {
			continue
		}
		found = true
		if !slices.Equal(block.feedback, wantAnswerFeedback) {
			t.Fatalf("answer VP8 feedback is %v, the offer carried %v and chrome answers with the LOCAL order filtered by the offer, %v, see NegotiateCodecs in pc/codec_vendor.cc which copies ours then calls IntersectFeedbackParams",
				block.feedback, remoteFeedback, wantAnswerFeedback)
		}
	}
	if !found {
		t.Fatal("answer carries no VP8 codec")
	}
}

func answerToOfferWithFeedback(t *testing.T, feedback []string) map[string]map[string]*codecBlock {
	t.Helper()

	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	offerer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new offerer: %v", err)
	}
	defer offerer.Close() //nolint:errcheck

	if _, err = offerer.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("add video transceiver: %v", err)
	}
	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	offer.SDP = rewriteFeedback(offer.SDP, feedback)

	answerer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new answerer: %v", err)
	}
	defer answerer.Close() //nolint:errcheck

	if err = answerer.SetRemoteDescription(offer); err != nil {
		t.Fatalf("set remote description: %v", err)
	}
	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}

	return parseCodecBlocks(answer.SDP)
}

func rewriteFeedback(sdp string, feedback []string) string {
	rewritten := []string{}
	for _, line := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(line, "a=rtcp-fb:") {
			continue
		}
		rewritten = append(rewritten, line)
		if !strings.HasPrefix(line, "a=rtpmap:") {
			continue
		}
		payloadType, description, _ := strings.Cut(strings.TrimPrefix(line, "a=rtpmap:"), " ")
		if strings.HasPrefix(strings.ToLower(description), "rtx/") {
			continue
		}
		for _, value := range feedback {
			rewritten = append(rewritten, "a=rtcp-fb:"+payloadType+" "+value)
		}
	}

	return strings.Join(rewritten, "\r\n")
}
