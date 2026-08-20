package headlessclient

import (
	"regexp"
	"strings"
	"testing"

	"github.com/kulikov0/headlessclient/webrtc"
)

var sdpICELine = regexp.MustCompile(`(?m)^a=ice-(ufrag|pwd):([^\r\n]*)`)

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
	settingEngine := webrtc.SettingEngine{}
	if err := ChromeWindows.ApplyICECredentials(&settingEngine); err != nil {
		t.Fatalf("apply ice credentials: %v", err)
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

func TestICECredentialsIgnoreNilEngine(t *testing.T) {
	if err := ChromeWindows.ApplyICECredentials(nil); err != nil {
		t.Fatalf("nil engine must be a no-op, got %v", err)
	}
}
