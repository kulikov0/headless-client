package headless

import (
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

func TestProfileRepeatsTheDTLSFingerprintInEveryMediaSection(t *testing.T) {
	profiles := []struct {
		name    string
		profile Profile
	}{
		{"default", ChromeWindows},
		{"dtls13 mimicry", ChromeWindows.WithDTLS13Mimicry()},
	}
	for _, candidate := range profiles {
		sessionFingerprints, sectionFingerprints := offerFingerprintCounts(t, candidate.profile)
		if sessionFingerprints != 0 {
			t.Fatalf("%s profile writes %d session level a=fingerprint, chrome writes none there and repeats the fingerprint in every m section",
				candidate.name, sessionFingerprints)
		}
		if len(sectionFingerprints) == 0 {
			t.Fatalf("%s profile produced an offer with no media sections", candidate.name)
		}
		for section, count := range sectionFingerprints {
			if count != 1 {
				t.Fatalf("%s profile writes %d a=fingerprint in media section %d, chrome writes exactly one",
					candidate.name, count, section)
			}
		}
	}
}

func offerFingerprintCounts(t *testing.T, profile Profile) (int, []int) {
	t.Helper()

	settingEngine, err := profile.SettingEngine()
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

	sessionFingerprints := 0
	sectionFingerprints := []int{}
	for _, line := range strings.Split(offer.SDP, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "m="):
			sectionFingerprints = append(sectionFingerprints, 0)
		case strings.HasPrefix(line, "a=fingerprint:"):
			if len(sectionFingerprints) == 0 {
				sessionFingerprints++

				continue
			}
			sectionFingerprints[len(sectionFingerprints)-1]++
		}
	}

	return sessionFingerprints, sectionFingerprints
}
