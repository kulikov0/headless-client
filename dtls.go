package headlessclient

import (
	"encoding/binary"
	"math/rand"

	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/handshake"
	"github.com/kulikov0/headlessclient/webrtc"
)

var greaseValues = [...]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

const (
	x25519MLKEM768Group = 0x11ec
	x25519Group         = 0x001d
)

var chromeDTLS13CipherSuiteIDs = []uint16{
	4865, 4866, 4867, 49195, 49199, 52393, 52392,
	49161, 49171, 49162, 49172, 156, 47, 53,
}

var chromeDTLS13SignatureAlgorithms = []uint16{
	0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
}

var chromeSRTPProtectionProfiles = []extension.SRTPProtectionProfile{
	extension.SRTP_AES128_CM_HMAC_SHA1_80,
	extension.SRTP_AEAD_AES_256_GCM,
	extension.SRTP_AEAD_AES_128_GCM,
}

var chromeDTLS13ExtensionOrder = []uint16{
	65281, 43, 45, 10, 51, 11, 13, 23, 14,
}

var chromeServerHelloExtensionOrder = []uint16{
	23, 65281, 11, 14,
}

func (p Profile) ApplyWebRTC(settingEngine *webrtc.SettingEngine) {
	if settingEngine == nil {
		return
	}
	settingEngine.SetSRTPProtectionProfiles(chromeSRTPProtectionProfiles...)
	settingEngine.SetDTLSServerHelloMessageHook(p.dtlsServerHelloHook)
	if p.dtls13Mimic {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtls13MimicHook)
		return
	}
	if p.dtlsShuffle || p.dtlsGREASE {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtlsClientHelloHook)
	}
}

func (p Profile) dtlsServerHelloHook(serverHello handshake.MessageServerHello) handshake.Message {
	serverHello.Extensions = orderExtensions(serverHello.Extensions, chromeServerHelloExtensionOrder)
	return &serverHello
}

func orderByCanonical[Item any, Key comparable](items []Item, canonicalOrder []Key, keyOf func(Item) Key) []Item {
	byKey := make(map[Key]Item, len(items))
	for _, item := range items {
		byKey[keyOf(item)] = item
	}

	ordered := make([]Item, 0, len(items))
	placed := make(map[Key]bool, len(canonicalOrder))
	for _, key := range canonicalOrder {
		if item, ok := byKey[key]; ok {
			ordered = append(ordered, item)
			placed[key] = true
		}
	}
	for _, item := range items {
		if !placed[keyOf(item)] {
			ordered = append(ordered, item)
		}
	}

	return ordered
}

func orderExtensions(extensions []extension.Value, canonicalOrder []uint16) []extension.Value {
	return orderByCanonical(extensions, canonicalOrder, func(value extension.Value) uint16 {
		return uint16(value.ExtensionType())
	})
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

func (p Profile) dtls13MimicHook(clientHello handshake.MessageClientHello) handshake.Message {
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
		signatureAlgorithms.Schemes = append([]uint16(nil), chromeDTLS13SignatureAlgorithms...)
	}

	if srtpOffer, ok := extensionsByType[14].(*extension.SRTPOffer); ok {
		srtpOffer.ProtectionProfiles = reorderSRTPProfiles(srtpOffer.ProtectionProfiles)
	}

	present := make([]extension.Value, 0, len(clientHello.Extensions)+1)
	present = append(present, clientHello.Extensions...)
	if _, ok := extensionsByType[45]; !ok {
		present = append(present, &dtls13.PSKKeyExchangeModes{
			Modes: []dtls13.PSKKeyExchangeMode{dtls13.PSKDHEKE},
		})
	}

	clientHello.Extensions = orderExtensions(present, chromeDTLS13ExtensionOrder)
	clientHello.CipherSuiteIDs = append([]uint16(nil), chromeDTLS13CipherSuiteIDs...)
	return &clientHello
}

func reorderSRTPProfiles(current []extension.SRTPProtectionProfile) []extension.SRTPProtectionProfile {
	return orderByCanonical(current, chromeSRTPProtectionProfiles, func(profile extension.SRTPProtectionProfile) extension.SRTPProtectionProfile {
		return profile
	})
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
