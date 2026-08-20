package headlessclient

import (
	"crypto/rand"

	"github.com/kulikov0/headlessclient/webrtc"
)

const (
	chromeICEUsernameFragmentLength = 4
	chromeICEPasswordLength         = 24
	iceCharacters                   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

func (p Profile) ApplyICECredentials(settingEngine *webrtc.SettingEngine) error {
	if settingEngine == nil {
		return nil
	}
	usernameFragment, err := randomICEString(chromeICEUsernameFragmentLength)
	if err != nil {
		return err
	}
	password, err := randomICEString(chromeICEPasswordLength)
	if err != nil {
		return err
	}
	settingEngine.SetICECredentials(usernameFragment, password)

	return nil
}

func randomICEString(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	for index, value := range buffer {
		buffer[index] = iceCharacters[int(value)%len(iceCharacters)]
	}

	return string(buffer), nil
}
