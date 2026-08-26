package headless

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
)

var sdpICELine = regexp.MustCompile(`(?m)^a=ice-(ufrag|pwd):([^\r\n]*)`)

func TestCallerSettingsOverwriteTheProfile(t *testing.T) {
	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}

	wantUsernameFragment := "ZZZZ"
	wantPassword := strings.Repeat("q", chromeICEPasswordLength)
	settingEngine.SetICECredentials(wantUsernameFragment, wantPassword)

	peerConnection, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer peerConnection.Close()

	if _, err = peerConnection.CreateDataChannel("probe", nil); err != nil {
		t.Fatalf("create data channel: %v", err)
	}
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	for _, match := range sdpICELine.FindAllStringSubmatch(offer.SDP, -1) {
		attribute, value := match[1], match[2]
		want := wantUsernameFragment
		if attribute == "pwd" {
			want = wantPassword
		}
		if value != want {
			t.Fatalf("a=ice-%s is %q, a setting applied after SettingEngine must overwrite the profile", attribute, value)
		}
	}
}

func TestVendoredICEKeepsTheKeepaliveIntervalPatch(t *testing.T) {
	const agentSource = "internal/ice/agent.go"

	source, err := os.ReadFile(agentSource)
	if err != nil {
		t.Fatalf("read %s: %v", agentSource, err)
	}
	if strings.Contains(string(source), "updateInterval(a.keepaliveInterval)") {
		t.Fatalf("%s went back to upstream, updateInterval only lowers the tick so any keepalive above the pion default of 2s is dropped and %v never reaches the wire",
			agentSource, chromeICEKeepaliveInterval)
	}
	if !strings.Contains(string(source), "interval = a.keepaliveInterval") {
		t.Fatalf("%s carries neither the patched assignment nor the upstream call, read it before trusting the keepalive cadence", agentSource)
	}
}

func TestICECredentialsHaveChromeShape(t *testing.T) {
	usernameFragment, err := randomICEString(chromeICEUsernameFragmentLength)
	if err != nil {
		t.Fatalf("generate username fragment: %v", err)
	}
	password, err := randomICEString(chromeICEPasswordLength)
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	if len(usernameFragment) != 4 {
		t.Fatalf("username fragment length = %d, chrome uses 4", len(usernameFragment))
	}
	if len(password) != 24 {
		t.Fatalf("password length = %d, chrome uses 24", len(password))
	}
	for _, character := range usernameFragment + password {
		if !strings.ContainsRune(iceCharacters, character) {
			t.Fatalf("character %q is outside the ice-char alphabet", character)
		}
	}
}

func TestICECredentialsDifferPerCall(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		value, err := randomICEString(chromeICEUsernameFragmentLength)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		seen[value] = true
	}
	if len(seen) < 40 {
		t.Fatalf("only %d distinct username fragments out of 50, generation looks degenerate", len(seen))
	}
}

func TestICECredentialsReachTheOffer(t *testing.T) {
	settingEngine, err := ChromeWindows.SettingEngine()
	if err != nil {
		t.Fatalf("setting engine: %v", err)
	}

	peerConnection, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("new peer connection: %v", err)
	}
	defer peerConnection.Close()

	if _, err = peerConnection.CreateDataChannel("probe", nil); err != nil {
		t.Fatalf("create data channel: %v", err)
	}
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}

	matches := sdpICELine.FindAllStringSubmatch(offer.SDP, -1)
	if len(matches) == 0 {
		t.Fatal("offer carries no ice credentials")
	}
	for _, match := range matches {
		attribute, value := match[1], match[2]
		wantLength := chromeICEUsernameFragmentLength
		if attribute == "pwd" {
			wantLength = chromeICEPasswordLength
		}
		if len(value) != wantLength {
			t.Fatalf("a=ice-%s is %d characters, chrome uses %d", attribute, len(value), wantLength)
		}
	}
}
