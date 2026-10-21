package headless

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/megamen32/headless-client/quic"
)

type QUICTransport int

const (
	QUICWebTransport QUICTransport = iota
	QUICHTTP3
)

const (
	boringSSLMLKEMDefaultChromeMajorVersion = 153
	quicInitialPacketSize                   = 1250
	quicConnectionIDLength                  = 0
	quicInitialMaxData                      = 15728640
	quicInitialMaxStreamData                = 6291456
	quicMaxIncomingStreams                  = 100
	quicMaxIncomingUniStreams               = 103
	quicMaxDatagramFrameSize                = 65536
	quicTransportParametersExtensionID      = 57
	quicVersionInformationParameterID       = 0x11
	quicGoogleConnectionOptionsParameterID  = 0x3128
	quicChosenVersion                       = 1
)

var (
	boringSSLDefaultSignatureAlgorithms = []utls.SignatureScheme{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
	}
	// chromeGoogleConnectionOptions is the token Chrome puts in the
	// google_connection_options transport parameter (0x3128). Chrome 155
	// sent "ORIG"; Chrome 156 sends "ORIGNOIP" (measured on the wire
	// 2026-10-21, Chrome 156.0.8078.47, HTTP/3). The token is Chrome's own
	// and changes with the release.
	chromeGoogleConnectionOptions = []byte("ORIGNOIP")
)

// chromeQUICCA34Extension is the unregistered extension Chrome sends in its
// QUIC hello, next to the ECH GREASE pair (measured on the wire 2026-10-21,
// Chrome 156.0.8078.47, HTTP/3). The bytes are the ones Chrome puts in the
// same extension of its TCP hello.
//
// Chrome 155 sent 11 extensions and fingerprinted as
// q13i0311h3_55b375c5d22e_178839b6cec1; Chrome 156 sends 12 and
// fingerprints as q13i0312h3_55b375c5d22e_eb028bd37c08. JA4 hashes extension
// IDs, not payloads.
var chromeQUICCA34Extension = utls.GenericExtension{
	Id:   0xCA34,
	Data: mustHex("00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f"),
}

// chromeQUIC12E0Extension is the unregistered extension Chrome 156 sends in
// its QUIC hello next to 0xCA34 (measured on the wire 2026-10-21 from a real
// Chrome 156.0.8078.47, macOS). Its payload is two zero bytes in every
// capture, in the QUIC hello as well as in the TCP one.
var chromeQUIC12E0Extension = utls.GenericExtension{
	Id:   0x12E0,
	Data: []byte{0x00, 0x00},
}

func boringSSLDefaultSupportedGroups() []utls.CurveID {
	groups := []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}
	if measuredChromeMajorVersion >= boringSSLMLKEMDefaultChromeMajorVersion {
		return append([]utls.CurveID{utls.X25519MLKEM768}, groups...)
	}

	return groups
}

func chromeQUICSupportedGroups(transport QUICTransport) []utls.CurveID {
	groups := boringSSLDefaultSupportedGroups()
	if transport != QUICHTTP3 {
		return groups
	}
	for _, group := range groups {
		if group == utls.X25519MLKEM768 {
			return groups
		}
	}

	return append([]utls.CurveID{utls.X25519MLKEM768}, groups...)
}

func chromeQUICKeyShares(groups []utls.CurveID) []utls.KeyShare {
	shares := make([]utls.KeyShare, 0, 2)
	for _, group := range groups {
		if group == utls.X25519MLKEM768 || group == utls.X25519 {
			shares = append(shares, utls.KeyShare{Group: group})
		}
	}

	return shares
}

func (p Profile) quicClientHelloSpec(transport QUICTransport, alpn []string) *utls.ClientHelloSpec {
	groups := chromeQUICSupportedGroups(transport)
	extensions := []utls.TLSExtension{
		&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
		&utls.SNIExtension{},
		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		&utls.GenericExtension{Id: quicTransportParametersExtensionID},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: boringSSLDefaultSignatureAlgorithms},
		&utls.ApplicationSettingsExtensionNew{SupportedProtocols: alpn},
		&utls.KeyShareExtension{KeyShares: chromeQUICKeyShares(groups)},
		&utls.SupportedCurvesExtension{Curves: groups},
		&utls.ALPNExtension{AlpnProtocols: alpn},
	}
	if transport == QUICHTTP3 {
		extensions = append(extensions, utls.BoringGREASEECH())
		// Chrome's QUIC hello carries the same two unregistered extensions
		// its TCP hello does: 0xCA34 and, since Chrome 156, 0x12E0.
		extensions = append(extensions, &chromeQUICCA34Extension, &chromeQUIC12E0Extension)
	}

	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS13,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256},
		CompressionMethods: []uint8{0},
		Extensions:         utls.ShuffleChromeTLSExtensions(extensions),
	}
}

func chromeGreasedQUICVersion() uint32 {
	var raw [4]byte
	rand.Read(raw[:])

	return binary.BigEndian.Uint32(raw[:])&0xf0f0f0f0 | 0x0a0a0a0a
}

func chromeQUICVersionInformation() []byte {
	out := make([]byte, 0, 12)
	out = binary.BigEndian.AppendUint32(out, quicChosenVersion)
	out = binary.BigEndian.AppendUint32(out, quicChosenVersion)
	out = binary.BigEndian.AppendUint32(out, chromeGreasedQUICVersion())

	return out
}

func chromeQUICTransportParameters(transport QUICTransport) map[uint64][]byte {
	parameters := map[uint64][]byte{
		quicVersionInformationParameterID: chromeQUICVersionInformation(),
	}
	if transport == QUICHTTP3 {
		parameters[quicGoogleConnectionOptionsParameterID] = chromeGoogleConnectionOptions
	}

	return parameters
}

type QUICOptions struct {
	Transport          QUICTransport
	ServerName         string
	ALPN               []string
	InsecureSkipVerify bool
	EnableDatagrams    bool
	KeepAlivePeriod    time.Duration
	MaxIdleTimeout     time.Duration
	KeyLogWriter       io.Writer
}

func (o QUICOptions) alpn() []string {
	if len(o.ALPN) > 0 {
		return o.ALPN
	}

	return []string{"h3"}
}

func (p Profile) QUICConfig(options QUICOptions) (*utls.Config, *quic.Config) {
	alpn := options.alpn()
	tlsConfig := &utls.Config{
		ServerName:         options.ServerName,
		InsecureSkipVerify: options.InsecureSkipVerify,
		NextProtos:         alpn,
		KeyLogWriter:       options.KeyLogWriter,
	}
	quicConfig := &quic.Config{
		EnableDatagrams:                options.EnableDatagrams,
		KeepAlivePeriod:                options.KeepAlivePeriod,
		MaxIdleTimeout:                 options.MaxIdleTimeout,
		TransportParameterOrder:        quic.TransportParameterOrderChrome,
		CachedClientHelloSpec:          p.quicClientHelloSpec(options.Transport, alpn),
		ConnectionIDLength:             quicConnectionIDLength,
		InitialPacketSize:              quicInitialPacketSize,
		MaxIncomingStreams:             quicMaxIncomingStreams,
		MaxIncomingUniStreams:          quicMaxIncomingUniStreams,
		InitialStreamReceiveWindow:     quicInitialMaxStreamData,
		InitialConnectionReceiveWindow: quicInitialMaxData,
		MaxDatagramFrameSize:           quicMaxDatagramFrameSize,
		AdditionalTransportParameters:  chromeQUICTransportParameters(options.Transport),
		DisableClientHelloScrambling:   true,
	}

	return tlsConfig, quicConfig
}

func (p Profile) DialQUIC(ctx context.Context, address string, options QUICOptions) (*quic.Conn, error) {
	if options.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		options.ServerName = host
	}
	tlsConfig, quicConfig := p.QUICConfig(options)

	return quic.DialAddrEarly(ctx, address, tlsConfig, quicConfig)
}
