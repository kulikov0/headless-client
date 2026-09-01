package rtpext

import "sync"

const (
	minimumID           = 1
	oneByteMaximumID    = 14
	unknownCanonicalPos = -1
)

type canonicalExtension struct {
	uri         string
	preferredID int
	offered     bool
}

var videoCanonicalExtensions = []canonicalExtension{
	{"urn:ietf:params:rtp-hdrext:toffset", 1, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time", 2, true},
	{"urn:3gpp:video-orientation", 3, true},
	{"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01", 4, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/playout-delay", 5, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/video-content-type", 6, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/video-timing", 7, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/color-space", 8, true},
	{"urn:ietf:params:rtp-hdrext:sdes:mid", 9, true},
	{"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", 10, true},
	{"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id", 11, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/corruption-detection", 12, false},
	{"http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time", 13, false},
	{"http://www.webrtc.org/experiments/rtp-hdrext/generic-frame-descriptor-00", 13, false},
	{"https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension", 13, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00", 13, true},
}

var audioCanonicalExtensions = []canonicalExtension{
	{"urn:ietf:params:rtp-hdrext:ssrc-audio-level", 1, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time", 2, true},
	{"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01", 3, true},
	{"urn:ietf:params:rtp-hdrext:sdes:mid", 4, true},
	{"http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time", 5, false},
}

func OfferedExtensions(video bool) []string {
	source := canonicalExtensionsFor(video)
	offered := make([]string, 0, len(source))
	for _, extension := range source {
		if extension.offered {
			offered = append(offered, extension.uri)
		}
	}

	return offered
}

func canonicalExtensionsFor(video bool) []canonicalExtension {
	if video {
		return videoCanonicalExtensions
	}

	return audioCanonicalExtensions
}

func PreferredID(uri string, video bool) int {
	for _, extension := range canonicalExtensionsFor(video) {
		if extension.uri == uri {
			return extension.preferredID
		}
	}

	return 0
}

func CanonicalPosition(uri string, video bool) int {
	for position, extension := range canonicalExtensionsFor(video) {
		if extension.uri == uri {
			return position
		}
	}

	return unknownCanonicalPos
}

type Picker struct {
	mutex          sync.Mutex
	idsByURI       map[string]int
	identifierSeen map[int]bool
}

func (p *Picker) Reserve(uri string, identifier int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.reserveLocked(uri, identifier)
}

func (p *Picker) reserveLocked(uri string, identifier int) {
	if p.idsByURI == nil {
		p.idsByURI = map[string]int{}
		p.identifierSeen = map[int]bool{}
	}
	if _, taken := p.idsByURI[uri]; !taken {
		p.idsByURI[uri] = identifier
	}
	p.identifierSeen[identifier] = true
}

func (p *Picker) Suggest(uri string, preferredID int) int {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if identifier, assigned := p.idsByURI[uri]; assigned {
		return identifier
	}

	if preferredID >= minimumID && preferredID <= oneByteMaximumID && !p.identifierSeen[preferredID] {
		p.reserveLocked(uri, preferredID)

		return preferredID
	}

	for identifier := oneByteMaximumID; identifier >= minimumID; identifier-- {
		if !p.identifierSeen[identifier] {
			p.reserveLocked(uri, identifier)

			return identifier
		}
	}

	return 0
}
