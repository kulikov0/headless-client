package headless

import (
	"fmt"

	"github.com/kulikov0/headless-client/internal/rtpext"
	"github.com/kulikov0/headless-client/webrtc"
)

func (p Profile) RegisterHeaderExtensions(mediaEngine *webrtc.MediaEngine) error {
	kinds := []struct {
		codecType webrtc.RTPCodecType
		video     bool
	}{
		{webrtc.RTPCodecTypeAudio, false},
		{webrtc.RTPCodecTypeVideo, true},
	}

	for _, kind := range kinds {
		for _, uri := range rtpext.OfferedExtensions(kind.video) {
			if err := mediaEngine.RegisterHeaderExtension(
				webrtc.RTPHeaderExtensionCapability{URI: uri}, kind.codecType,
			); err != nil {
				return fmt.Errorf("register header extension %s: %w", uri, err)
			}
		}
	}

	return nil
}
