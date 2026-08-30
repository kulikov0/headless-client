package headless

import (
	"encoding/binary"
	"math/rand"
	"slices"
	"time"

	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/handshake"
	"github.com/kulikov0/headless-client/webrtc"
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

var chromeServerHelloExtensionOrder = []uint16{
	23, 65281, 11, 14,
}

var chromeDTLS13ServerHelloExtensionOrder = []uint16{
	51, 43,
}

// chromeICEKeepaliveInterval is measured. libwebrtc sets
// kStrongAndStableWritableConnectionPingInterval to 2500ms in
// p2p/base/p2p_constants.h. Chrome sends 2656ms on the wire. The 156ms
// difference is unexplained.
//
// The value reproduced across five captures, two machines, three services and
// RTTs from 0.05ms to 60ms, with medians within 0.5ms of each other. It is not
// RTT, not capture noise and not drift.
//
// All reference captures are Chrome on Linux in a container. This profile
// claims Windows. The value is unverified on Windows. Investigate later.
const (
	chromeICEKeepaliveInterval        = 2656 * time.Millisecond
	pionDefaultICEDisconnectedTimeout = 5 * time.Second
	pionDefaultICEFailedTimeout       = 25 * time.Second
)

func (p Profile) SettingEngine() (webrtc.SettingEngine, error) {
	settingEngine := webrtc.SettingEngine{}
	p.applyWebRTC(&settingEngine)
	if err := p.applyICECredentials(&settingEngine); err != nil {
		return webrtc.SettingEngine{}, err
	}

	return settingEngine, nil
}

func (p Profile) applyWebRTC(settingEngine *webrtc.SettingEngine) {
	settingEngine.SetSRTPProtectionProfiles(chromeSRTPProtectionProfiles...)
	settingEngine.SetICETimeouts(pionDefaultICEDisconnectedTimeout, pionDefaultICEFailedTimeout, chromeICEKeepaliveInterval)
	settingEngine.SetDTLSServerHelloMessageHook(p.dtlsServerHelloHook)
	settingEngine.SetDTLSInsecureSkipHelloVerify(true)
	if p.dtls13Mimic {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtls13MimicHook)
		return
	}
	if p.dtlsShuffle || p.dtlsGREASE {
		settingEngine.SetDTLSClientHelloMessageHook(p.dtlsClientHelloHook)
	}
}

func (p Profile) dtlsServerHelloHook(serverHello handshake.MessageServerHello) handshake.Message {
	order := chromeServerHelloExtensionOrder
	if offersExtension(serverHello.Extensions, extension.TypeSupportedVersions) {
		order = chromeDTLS13ServerHelloExtensionOrder
	}
	serverHello.Extensions = orderExtensions(serverHello.Extensions, order)
	return &serverHello
}

func offersExtension(extensions []extension.Value, extensionType extension.Type) bool {
	return slices.ContainsFunc(extensions, func(value extension.Value) bool {
		return value.ExtensionType() == extensionType
	})
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

	if p.dtlsShuffle {
		shuffleExtensions(extensions, source)
	}
	if p.dtlsGREASE {
		extensions = wrapInGREASE(extensions, source)
	}

	clientHello.Extensions = extensions
	return &clientHello
}

func shuffleExtensions(extensions []extension.Value, source *rand.Rand) {
	source.Shuffle(len(extensions), func(first, second int) {
		extensions[first], extensions[second] = extensions[second], extensions[first]
	})
}

func wrapInGREASE(extensions []extension.Value, source *rand.Rand) []extension.Value {
	first := greaseValues[source.Intn(len(greaseValues))]
	last := greaseValues[source.Intn(len(greaseValues))]

	wrapped := make([]extension.Value, 0, len(extensions)+2)
	wrapped = append(wrapped, greaseExtension{value: first})
	wrapped = append(wrapped, extensions...)
	wrapped = append(wrapped, greaseExtension{value: last, data: []byte{0}})

	return wrapped
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

	source := rand.New(rand.NewSource(seedFromRandom(clientHello.Random)))
	if p.dtlsShuffle {
		shuffleExtensions(present, source)
	}
	if p.dtlsGREASE {
		present = wrapInGREASE(present, source)
	}

	clientHello.Extensions = present
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
	data  []byte
}

func (g greaseExtension) ExtensionType() extension.Type {
	return extension.Type(g.value)
}

func (g greaseExtension) MarshalSize() int {
	return len(g.data)
}

func (g greaseExtension) MarshalData() ([]byte, error) {
	if g.data == nil {
		return []byte{}, nil
	}

	return g.data, nil
}
