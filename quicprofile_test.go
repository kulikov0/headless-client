package headless

import (
	"slices"
	"testing"

	utls "github.com/refraction-networking/utls"
)

var (
	chromeWebTransportExtensions  = []uint16{0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd}
	chromeWebTransportGroups      = []utls.CurveID{0x001d, 0x0017, 0x0018}
	chromeQUICSignatureAlgorithms = []utls.SignatureScheme{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
	}
	chromeQUICCipherSuites = []uint16{0x1301, 0x1302, 0x1303}
)

func specExtensionIDs(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	ids := make([]uint16, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.SNIExtension:
			ids = append(ids, 0x0000)
		case *utls.SupportedCurvesExtension:
			ids = append(ids, 0x000a)
		case *utls.SignatureAlgorithmsExtension:
			ids = append(ids, 0x000d)
		case *utls.ALPNExtension:
			ids = append(ids, 0x0010)
		case *utls.UtlsCompressCertExtension:
			ids = append(ids, 0x001b)
		case *utls.SupportedVersionsExtension:
			ids = append(ids, 0x002b)
		case *utls.PSKKeyExchangeModesExtension:
			ids = append(ids, 0x002d)
		case *utls.KeyShareExtension:
			ids = append(ids, 0x0033)
		case *utls.ApplicationSettingsExtensionNew:
			ids = append(ids, 0x44cd)
		case *utls.GREASEEncryptedClientHelloExtension:
			ids = append(ids, 0xfe0d)
		case *utls.GenericExtension:
			ids = append(ids, typed.Id)
		default:
			t.Fatalf("unhandled extension type %T", extension)
		}
	}
	slices.Sort(ids)

	return ids
}

func TestWebTransportHelloCarriesTheBoringSSLDefaults(t *testing.T) {
	spec := ChromeWindows.quicClientHelloSpec(QUICWebTransport, []string{"h3"})

	if !slices.Equal(spec.CipherSuites, chromeQUICCipherSuites) {
		t.Fatalf("cipher suites %#04x, the chrome capture carries %#04x with no GREASE", spec.CipherSuites, chromeQUICCipherSuites)
	}

	ids := specExtensionIDs(t, spec)
	if !slices.Equal(ids, chromeWebTransportExtensions) {
		t.Fatalf("extension set %#04x, the chrome webtransport capture carries %#04x", ids, chromeWebTransportExtensions)
	}

	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.SupportedCurvesExtension:
			want := chromeWebTransportGroups
			if measuredChromeMajorVersion >= boringSSLMLKEMDefaultChromeMajorVersion {
				want = append([]utls.CurveID{0x11ec}, want...)
			}
			if !slices.Equal(typed.Curves, want) {
				t.Fatalf("groups %#04x, DefaultSupportedGroupIds for chrome %d is %#04x", typed.Curves, measuredChromeMajorVersion, want)
			}
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Equal(typed.SupportedSignatureAlgorithms, chromeQUICSignatureAlgorithms) {
				t.Fatalf("signature algorithms %#04x, kVerifySignatureAlgorithms is %#04x", typed.SupportedSignatureAlgorithms, chromeQUICSignatureAlgorithms)
			}
		}
	}
}

func TestHTTP3HelloAddsWhatTheSessionPoolConfigures(t *testing.T) {
	webTransport := specExtensionIDs(t, ChromeWindows.quicClientHelloSpec(QUICWebTransport, []string{"h3"}))
	http3 := specExtensionIDs(t, ChromeWindows.quicClientHelloSpec(QUICHTTP3, []string{"h3"}))

	if len(http3) != len(webTransport)+1 {
		t.Fatalf("http3 carries %d extensions and webtransport %d; the only documented difference is the ECH extension", len(http3), len(webTransport))
	}
	if !slices.Contains(http3, 0xfe0d) {
		t.Fatalf("http3 extensions %#04x carry no ECH, but QuicChromiumClientSession::GetSSLConfig sets ech_grease_enabled", http3)
	}

	spec := ChromeWindows.quicClientHelloSpec(QUICHTTP3, []string{"h3"})
	for _, extension := range spec.Extensions {
		curves, ok := extension.(*utls.SupportedCurvesExtension)
		if !ok {
			continue
		}
		if !slices.Contains(curves.Curves, utls.X25519MLKEM768) {
			t.Fatalf("http3 groups %v lack the post-quantum group that quic_session_pool.cc sets through set_preferred_groups", curves.Curves)
		}
	}
}

func TestQUICConfigCarriesTheChromeTransportParameters(t *testing.T) {
	_, webTransport := ChromeWindows.QUICConfig(QUICOptions{Transport: QUICWebTransport})
	if webTransport.TransportParameterOrder != 1 {
		t.Fatalf("transport parameter order %d, chrome shuffles and the fork calls that mode 1", webTransport.TransportParameterOrder)
	}
	if webTransport.InitialPacketSize != 1258 {
		t.Fatalf("initial packet size %d, the chrome capture pads its initial datagram to 1258", webTransport.InitialPacketSize)
	}
	if webTransport.MaxIncomingUniStreams != 103 {
		t.Fatalf("initial_max_streams_uni %d, chrome sends 103", webTransport.MaxIncomingUniStreams)
	}
	if webTransport.MaxIncomingStreams != 100 {
		t.Fatalf("initial_max_streams_bidi %d, chrome sends 100", webTransport.MaxIncomingStreams)
	}
	if webTransport.InitialConnectionReceiveWindow != 15728640 {
		t.Fatalf("initial_max_data %d, chrome sends 15728640", webTransport.InitialConnectionReceiveWindow)
	}
	if webTransport.InitialStreamReceiveWindow != 6291456 {
		t.Fatalf("initial_max_stream_data %d, chrome sends 6291456", webTransport.InitialStreamReceiveWindow)
	}
	if webTransport.MaxDatagramFrameSize != 65536 {
		t.Fatalf("max_datagram_frame_size %d, chrome sends 65536", webTransport.MaxDatagramFrameSize)
	}
	if webTransport.ConnectionIDLength != 0 {
		t.Fatalf("connection id length %d, the chrome capture carries an empty initial_source_connection_id", webTransport.ConnectionIDLength)
	}
	information, ok := webTransport.AdditionalTransportParameters[0x11]
	if !ok || len(information) != 12 {
		t.Fatalf("version_information is %d bytes, chrome sends id 0x11 with twelve", len(information))
	}
	if _, ok := webTransport.AdditionalTransportParameters[0x3128]; ok {
		t.Fatal("webtransport carries google_connection_options; the capture shows it only on the http3 path")
	}

	_, http3 := ChromeWindows.QUICConfig(QUICOptions{Transport: QUICHTTP3})
	if _, ok := http3.AdditionalTransportParameters[0x3128]; !ok {
		t.Fatal("http3 carries no google_connection_options, but the capture shows id 0x3128 on every h3 connection")
	}
}

func TestQUICVersionInformationIsGreased(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		information := chromeQUICVersionInformation()
		if len(information) != 12 {
			t.Fatalf("version_information is %d bytes, chrome sends 12", len(information))
		}
		greased := uint32(information[8])<<24 | uint32(information[9])<<16 | uint32(information[10])<<8 | uint32(information[11])
		if greased&0x0f0f0f0f != 0x0a0a0a0a {
			t.Fatalf("available version %#08x is not a greased version", greased)
		}
	}
}
