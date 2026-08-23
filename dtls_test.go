package headlessclient

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/kulikov0/headlessclient/internal/dtls/pkg/crypto/elliptic"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension/dtls12"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headlessclient/internal/dtls/pkg/protocol/handshake"
)

func pionDefaultClientHello(randomByte byte) handshake.MessageClientHello {
	var random handshake.Random
	for i := range random.RandomBytes {
		random.RandomBytes[i] = randomByte
	}
	return handshake.MessageClientHello{
		Random: random,
		Extensions: []extension.Value{
			&dtls12.RenegotiationInfo{RenegotiatedConnection: 0},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&dtls12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}},
			&dtls12.ExtendedMasterSecret{},
		},
	}
}

func extensionOrder(message handshake.Message) []extension.Type {
	clientHello, ok := message.(*handshake.MessageClientHello)
	if !ok {
		return nil
	}
	order := make([]extension.Type, 0, len(clientHello.Extensions))
	for _, ext := range clientHello.Extensions {
		order = append(order, ext.ExtensionType())
	}
	return order
}

func TestDTLSClientHelloShuffleMovesSupportedGroups(t *testing.T) {
	distinctOrders := map[string]bool{}
	groupPositions := map[int]bool{}
	for seed := byte(1); seed <= 20; seed++ {
		output := ChromeWindows.dtlsClientHelloHook(pionDefaultClientHello(seed))
		order := extensionOrder(output)
		distinctOrders[fmt.Sprint(order)] = true
		for position, extensionType := range order {
			if extensionType == extension.TypeSupportedGroups {
				groupPositions[position] = true
			}
		}
	}
	if len(distinctOrders) < 2 {
		t.Fatalf("expected shuffled extension orders to vary, got %d distinct", len(distinctOrders))
	}
	if len(groupPositions) < 2 {
		t.Fatalf("expected supported_groups position to move across handshakes, got %d distinct", len(groupPositions))
	}
}

func TestDTLSClientHelloInjectsGREASE(t *testing.T) {
	order := extensionOrder(ChromeWindows.dtlsClientHelloHook(pionDefaultClientHello(7)))
	found := false
	for _, extensionType := range order {
		for _, greaseValue := range greaseValues {
			if uint16(extensionType) == greaseValue {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected a GREASE extension in the client hello")
	}
}

func pion13ClientHello() handshake.MessageClientHello {
	var random handshake.Random
	for i := range random.RandomBytes {
		random.RandomBytes[i] = 0x11
	}
	groups := []elliptic.Curve{x25519MLKEM768Group, elliptic.X25519, 23, 24}
	clientShares := make([]dtls13.KeyShareEntry, 0, len(groups))
	for _, group := range groups {
		clientShares = append(clientShares, dtls13.KeyShareEntry{Group: group, KeyExchange: []byte{1, 2, 3, 4}})
	}
	return handshake.MessageClientHello{
		Random:         random,
		CipherSuiteIDs: []uint16{4865, 4866, 4867, 49195, 49199},
		Extensions: []extension.Value{
			&extension.SupportedGroups{Groups: groups},
			&dtls13.ClientKeyShare{Shares: clientShares},
			&dtls12.RenegotiationInfo{RenegotiatedConnection: 0},
			&dtls13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3, protocol.Version1_2}},
			&extension.SignatureAlgorithms{Schemes: []uint16{0x0201, 0x0401}},
			&dtls12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}},
			&dtls12.ExtendedMasterSecret{},
			&extension.SRTPOffer{ProtectionProfiles: []extension.SRTPProtectionProfile{
				extension.SRTP_AEAD_AES_256_GCM,
				extension.SRTP_AEAD_AES_128_GCM,
				extension.SRTP_AES128_CM_HMAC_SHA1_80,
			}},
		},
	}
}

func findSRTPOffer(extensions []extension.Value) *extension.SRTPOffer {
	for _, ext := range extensions {
		if srtpOffer, ok := ext.(*extension.SRTPOffer); ok {
			return srtpOffer
		}
	}
	return nil
}

func findKeyShare(extensions []extension.Value) *dtls13.ClientKeyShare {
	for _, ext := range extensions {
		if keyShare, ok := ext.(*dtls13.ClientKeyShare); ok {
			return keyShare
		}
	}
	return nil
}

func findSignatureAlgorithms(extensions []extension.Value) *extension.SignatureAlgorithms {
	for _, ext := range extensions {
		if sigAlgs, ok := ext.(*extension.SignatureAlgorithms); ok {
			return sigAlgs
		}
	}
	return nil
}

func TestDTLS13Mimicry(t *testing.T) {
	output, ok := ChromeWindows.WithDTLS13Mimicry().dtls13MimicHook(pion13ClientHello()).(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("mimic hook did not return a client hello")
	}

	if fmt.Sprint(output.CipherSuiteIDs) != fmt.Sprint(chromeDTLS13CipherSuiteIDs) {
		t.Fatalf("ciphers = %v, want %v", output.CipherSuiteIDs, chromeDTLS13CipherSuiteIDs)
	}

	wantOrder := []extension.Type{65281, 43, 45, 10, 51, 11, 13, 23, 14}
	if got := extensionOrder(output); fmt.Sprint(got) != fmt.Sprint(wantOrder) {
		t.Fatalf("extension order = %v, want %v", got, wantOrder)
	}

	keyShare := findKeyShare(output.Extensions)
	if keyShare == nil {
		t.Fatal("key_share missing after mimic")
	}
	if len(keyShare.Shares) != 2 ||
		uint16(keyShare.Shares[0].Group) != x25519MLKEM768Group ||
		uint16(keyShare.Shares[1].Group) != x25519Group {
		t.Fatalf("key_share = %v, want [0x11ec 0x001d]", keyShare.Shares)
	}

	sigAlgs := findSignatureAlgorithms(output.Extensions)
	if sigAlgs == nil {
		t.Fatal("signature_algorithms missing after mimic")
	}
	if fmt.Sprint(sigAlgs.Schemes) != fmt.Sprint(chromeDTLS13SignatureAlgorithms) {
		t.Fatalf("signature_algorithms = %v, want %v", sigAlgs.Schemes, chromeDTLS13SignatureAlgorithms)
	}

	srtpOffer := findSRTPOffer(output.Extensions)
	if srtpOffer == nil {
		t.Fatal("use_srtp missing after mimic")
	}
	if fmt.Sprint(srtpOffer.ProtectionProfiles) != fmt.Sprint(chromeSRTPProtectionProfiles) {
		t.Fatalf("use_srtp = %v, want %v", srtpOffer.ProtectionProfiles, chromeSRTPProtectionProfiles)
	}

	if _, err := output.Marshal(); err != nil {
		t.Fatalf("marshal mimic client hello: %v", err)
	}
}

func TestDTLSClientHelloStableForSameRandom(t *testing.T) {
	firstBytes, err := ChromeWindows.dtlsClientHelloHook(pionDefaultClientHello(9)).Marshal()
	if err != nil {
		t.Fatalf("marshal first client hello: %v", err)
	}
	secondBytes, err := ChromeWindows.dtlsClientHelloHook(pionDefaultClientHello(9)).Marshal()
	if err != nil {
		t.Fatalf("marshal second client hello: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same client random must produce an identical client hello across flights")
	}
}

func pionDefaultServerHello() handshake.MessageServerHello {
	cipherSuiteID := uint16(0xc02b)

	return handshake.MessageServerHello{
		Version:           protocol.Version{Major: 0xfe, Minor: 0xfd},
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: protocol.CompressionMethods()[0],
		Extensions: []extension.Value{
			&dtls12.ExtendedMasterSecret{},
			&extension.SRTPSelection{ProtectionProfile: extension.SRTP_AEAD_AES_256_GCM},
			&dtls12.RenegotiationInfo{RenegotiatedConnection: 0},
			&dtls12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}},
		},
	}
}

func serverHelloExtensionOrder(message handshake.Message) []extension.Type {
	serverHello, ok := message.(*handshake.MessageServerHello)
	if !ok {
		return nil
	}
	order := make([]extension.Type, 0, len(serverHello.Extensions))
	for _, ext := range serverHello.Extensions {
		order = append(order, ext.ExtensionType())
	}

	return order
}

func TestDTLSServerHelloUsesChromeExtensionOrder(t *testing.T) {
	input := pionDefaultServerHello()
	before := serverHelloExtensionOrder(&input)
	if fmt.Sprint(before) != fmt.Sprint([]extension.Type{23, 14, 65281, 11}) {
		t.Fatalf("fixture is not the pion order, got %v", before)
	}

	output := ChromeWindows.dtlsServerHelloHook(pionDefaultServerHello())
	after := serverHelloExtensionOrder(output)
	if fmt.Sprint(after) != fmt.Sprint([]extension.Type{23, 65281, 11, 14}) {
		t.Fatalf("server hello order = %v, want the chrome order [23 65281 11 14]", after)
	}

	if _, err := output.Marshal(); err != nil {
		t.Fatalf("marshal server hello: %v", err)
	}
}

func TestDTLSServerHelloKeepsUnknownExtensions(t *testing.T) {
	input := pionDefaultServerHello()
	input.Extensions = append(input.Extensions, greaseExtension{value: 0x3a3a})

	after := serverHelloExtensionOrder(ChromeWindows.dtlsServerHelloHook(input))
	if fmt.Sprint(after) != fmt.Sprint([]extension.Type{23, 65281, 11, 14, 0x3a3a}) {
		t.Fatalf("server hello order = %v, an unordered extension must survive at the end", after)
	}
}

func TestChromeSRTPProfileOrderSelectsSHA1OverGCM(t *testing.T) {
	if chromeSRTPProtectionProfiles[0] != extension.SRTP_AES128_CM_HMAC_SHA1_80 {
		t.Fatalf("first profile = %v, chrome offers SRTP_AES128_CM_HMAC_SHA1_80 first", chromeSRTPProtectionProfiles[0])
	}

	peerOffer := []extension.SRTPProtectionProfile{
		extension.SRTP_AEAD_AES_256_GCM,
		extension.SRTP_AEAD_AES_128_GCM,
		extension.SRTP_AES128_CM_HMAC_SHA1_80,
	}
	var selected extension.SRTPProtectionProfile
	for _, candidate := range chromeSRTPProtectionProfiles {
		if slices.Contains(peerOffer, candidate) {
			selected = candidate

			break
		}
	}
	if selected != extension.SRTP_AES128_CM_HMAC_SHA1_80 {
		t.Fatalf("selected profile = %v, want SRTP_AES128_CM_HMAC_SHA1_80", selected)
	}
}
