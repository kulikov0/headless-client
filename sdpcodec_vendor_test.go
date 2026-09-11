package headless

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

type codecBlock struct {
	attributeOrder []string
	feedback       []string
	name           string
}

func TestVendoredWebRTCEmitsTheChromeCodecBlockOrder(t *testing.T) {
	sections := offerCodecBlocks(t)

	for _, payloadType := range slices.Sorted(maps(sections["video"])) {
		block := sections["video"][payloadType]
		if !strings.HasPrefix(block.attributeOrder[0], "rtpmap") {
			t.Fatalf("video payload type %s starts with %s, chrome starts every codec with a=rtpmap",
				payloadType, block.attributeOrder[0])
		}
		lastFeedback := slices.Index(reverse(block.attributeOrder), "rtcp-fb")
		fmtpIndex := slices.Index(block.attributeOrder, "fmtp")
		if fmtpIndex < 0 || lastFeedback < 0 {
			continue
		}
		if fmtpIndex < len(block.attributeOrder)-1-lastFeedback {
			t.Fatalf("video payload type %s emits a=fmtp before a=rtcp-fb, chrome emits rtpmap then every rtcp-fb then fmtp, see BuildRtpmap in api/webrtc_sdp.cc",
				payloadType)
		}
	}
}

func TestVendoredWebRTCOrdersVideoFeedbackLikeChrome(t *testing.T) {
	chromeOrder := []string{"goog-remb", "transport-cc", "ccm fir", "nack", "nack pli"}
	sections := offerCodecBlocks(t)

	found := false
	for _, block := range sections["video"] {
		if block.name != "VP8/90000" {
			continue
		}
		found = true
		if !slices.Equal(block.feedback, chromeOrder) {
			t.Fatalf("VP8 feedback is %v, chrome adds them in the fixed order %v, see AddDefaultFeedbackParams in media/base/codec.cc",
				block.feedback, chromeOrder)
		}
	}
	if !found {
		t.Fatal("offer carries no VP8 codec")
	}
}

func TestVendoredWebRTCGivesTransportCCToOpusAlone(t *testing.T) {
	sections := offerCodecBlocks(t)

	for payloadType, block := range sections["audio"] {
		want := []string{}
		if strings.HasPrefix(block.name, "opus/") {
			want = []string{"transport-cc"}
		}
		if !slices.Equal(block.feedback, want) {
			t.Fatalf("audio codec %s payload type %s carries feedback %v, chrome gives transport-cc only where supports_network_adaption is set, which is opus alone, see typed_codec_vendor.cc",
				block.name, payloadType, block.feedback)
		}
	}
}

func TestVendoredWebRTCGivesResiliencyCodecsNoFeedback(t *testing.T) {
	sections := offerCodecBlocks(t)

	checked := 0
	for kind, blocks := range sections {
		for payloadType, block := range blocks {
			encodingName, _, _ := strings.Cut(block.name, "/")
			switch strings.ToLower(encodingName) {
			case "rtx", "red", "ulpfec", "flexfec-03":
			default:
				continue
			}
			checked++
			if len(block.feedback) != 0 {
				t.Fatalf("%s resiliency codec %s payload type %s carries feedback %v, chrome skips resiliency codecs before AddDefaultFeedbackParams, see typed_codec_vendor.cc IsResiliencyCodec",
					kind, block.name, payloadType, block.feedback)
			}
		}
	}
	if checked == 0 {
		t.Fatal("offer carries no resiliency codec, the guard proved nothing")
	}
}

func TestVendoredWebRTCGivesEveryChromeResiliencyNameNoFeedback(t *testing.T) {
	resiliencyCodecs := []struct {
		mimeType    string
		payloadType webrtc.PayloadType
	}{
		{"video/red", 120},
		{"video/ulpfec", 121},
		{"video/flexfec-03", 122},
	}

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("register default codecs: %v", err)
	}
	for _, codec := range resiliencyCodecs {
		err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: codec.mimeType, ClockRate: 90000},
			PayloadType:        codec.payloadType,
		}, webrtc.RTPCodecTypeVideo)
		if err != nil {
			t.Fatalf("register %s: %v", codec.mimeType, err)
		}
	}

	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine), webrtc.WithMediaEngine(mediaEngine))
	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer peerConnection.Close() //nolint:errcheck

	if _, err = peerConnection.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatalf("add video transceiver: %v", err)
	}
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	blocks := parseCodecBlocks(offer.SDP)["video"]
	for _, codec := range resiliencyCodecs {
		block := blocks[strconv.Itoa(int(codec.payloadType))]
		if block == nil {
			t.Fatalf("%s never reached the offer, the guard proved nothing", codec.mimeType)
		}
		if len(block.feedback) != 0 {
			t.Fatalf("%s carries feedback %v, Codec::GetResiliencyType in media/base/codec.cc names red, ulpfec, flexfec-03 and rtx, and pc/typed_codec_vendor.cc skips every one of them before AddDefaultFeedbackParams",
				codec.mimeType, block.feedback)
		}
	}
}

func maps(blocks map[string]*codecBlock) func(func(string) bool) {
	return func(yield func(string) bool) {
		for payloadType := range blocks {
			if !yield(payloadType) {
				return
			}
		}
	}
}

func reverse(values []string) []string {
	out := slices.Clone(values)
	slices.Reverse(out)

	return out
}

func offerCodecBlocks(t *testing.T) map[string]map[string]*codecBlock {
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
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	return parseCodecBlocks(offer.SDP)
}

func parseCodecBlocks(sdp string) map[string]map[string]*codecBlock {
	sections := map[string]map[string]*codecBlock{}
	kind := ""
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "m=") {
			kind = strings.TrimPrefix(strings.Fields(line)[0], "m=")
			sections[kind] = map[string]*codecBlock{}

			continue
		}
		attribute, value, found := strings.Cut(strings.TrimPrefix(line, "a="), ":")
		if !found || kind == "" {
			continue
		}
		payloadType, rest, _ := strings.Cut(value, " ")
		if attribute != "rtpmap" && attribute != "fmtp" && attribute != "rtcp-fb" {
			continue
		}
		block := sections[kind][payloadType]
		if block == nil {
			block = &codecBlock{}
			sections[kind][payloadType] = block
		}
		block.attributeOrder = append(block.attributeOrder, attribute)
		switch attribute {
		case "rtpmap":
			block.name = rest
		case "rtcp-fb":
			block.feedback = append(block.feedback, rest)
		}
	}

	return sections
}
