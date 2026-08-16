package headlessclient

import (
	"encoding/binary"
	"math/rand"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/webrtc/v4"
)

var greaseValues = [...]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

const (
	x25519MLKEM768Group = 0x11ec
	x25519Group         = 0x001d
)

var chrome13CipherSuiteIDs = []uint16{
	4865, 4866, 4867, 49195, 49199, 52393, 52392,
	49161, 49171, 49162, 49172, 156, 47, 53,
}

var chrome13SignatureAlgorithms = []uint16{
	0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
}

var chrome13SRTPProtectionProfiles = []extension.SRTPProtectionProfile{
	extension.SRTP_AES128_CM_HMAC_SHA1_80,
	extension.SRTP_AEAD_AES_256_GCM,
	extension.SRTP_AEAD_AES_128_GCM,
}

var chrome13ExtensionOrder = []uint16{
	65281, 43, 45, 10, 51, 11, 13, 23, 14,
}

func (p Profile) ApplyWebRTC(settingEngine *webrtc.SettingEngine) {
	if settingEngine == nil {
		return
	}
	if p.dtlsMimicChrome13 {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtlsMimicChrome13Hook)
		return
	}
	if p.dtlsShuffle || p.dtlsGREASE {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtlsClientHelloHook)
	}
}

func (p Profile) dtlsClientHelloHook(clientHello handshake.MessageClientHello) handshake.Message {
	source := rand.New(rand.NewSource(seedFromRandom(clientHello.Random)))

	extensions := make([]extension.Value, len(clientHello.Extensions))
	copy(extensions, clientHello.Extensions)

	if p.dtlsGREASE {
		greaseValue := greaseValues[source.Intn(len(greaseValues))]
		extensions = append(extensions, greaseExtension{value: greaseValue})
	}
	if p.dtlsShuffle {
		source.Shuffle(len(extensions), func(first, second int) {
			extensions[first], extensions[second] = extensions[second], extensions[first]
		})
	}

	clientHello.Extensions = extensions
	return &clientHello
}

func (p Profile) dtlsMimicChrome13Hook(clientHello handshake.MessageClientHello) handshake.Message {
	extensionsByType := make(map[uint16]extension.Value, len(clientHello.Extensions))
	for _, ext := range clientHello.Extensions {
		extensionsByType[uint16(ext.ExtensionType())] = ext
	}

	if keyShare, ok := extensionsByType[51].(*dtls13.ClientKeyShare); ok {
		var browserShares []dtls13.KeyShareEntry
		for _, share := range keyShare.Shares {
			if uint16(share.Group) == x25519MLKEM768Group || uint16(share.Group) == x25519Group {
				browserShares = append(browserShares, share)
			}
		}
		keyShare.Shares = browserShares
	}

	if signatureAlgorithms, ok := extensionsByType[13].(*extension.SignatureAlgorithms); ok {
		signatureAlgorithms.Schemes = append([]uint16(nil), chrome13SignatureAlgorithms...)
	}

	if srtpOffer, ok := extensionsByType[14].(*extension.SRTPOffer); ok {
		srtpOffer.ProtectionProfiles = reorderSRTPProfiles(srtpOffer.ProtectionProfiles)
	}

	if _, ok := extensionsByType[45]; !ok {
		extensionsByType[45] = &dtls13.PSKKeyExchangeModes{
			Modes: []dtls13.PSKKeyExchangeMode{dtls13.PSKDHEKE},
		}
	}

	ordered := make([]extension.Value, 0, len(clientHello.Extensions))
	placed := make(map[uint16]bool, len(chrome13ExtensionOrder))
	for _, extensionType := range chrome13ExtensionOrder {
		if ext, ok := extensionsByType[extensionType]; ok {
			ordered = append(ordered, ext)
			placed[extensionType] = true
		}
	}
	for _, ext := range clientHello.Extensions {
		if !placed[uint16(ext.ExtensionType())] {
			ordered = append(ordered, ext)
		}
	}

	clientHello.Extensions = ordered
	clientHello.CipherSuiteIDs = append([]uint16(nil), chrome13CipherSuiteIDs...)
	return &clientHello
}

func reorderSRTPProfiles(current []extension.SRTPProtectionProfile) []extension.SRTPProtectionProfile {
	present := make(map[extension.SRTPProtectionProfile]bool, len(current))
	for _, profile := range current {
		present[profile] = true
	}
	reordered := make([]extension.SRTPProtectionProfile, 0, len(current))
	placed := make(map[extension.SRTPProtectionProfile]bool, len(chrome13SRTPProtectionProfiles))
	for _, profile := range chrome13SRTPProtectionProfiles {
		if present[profile] {
			reordered = append(reordered, profile)
			placed[profile] = true
		}
	}
	for _, profile := range current {
		if !placed[profile] {
			reordered = append(reordered, profile)
		}
	}
	return reordered
}

func seedFromRandom(random handshake.Random) int64 {
	return int64(binary.BigEndian.Uint64(random.RandomBytes[:8]))
}

type greaseExtension struct {
	value uint16
}

func (g greaseExtension) ExtensionType() extension.Type {
	return extension.Type(g.value)
}

func (g greaseExtension) MarshalData() ([]byte, error) {
	return []byte{}, nil
}
