package headless

import (
	utls "github.com/refraction-networking/utls"
)

// Safari parrots, built from full ClientHello captures on real Macs
// (2026-09-10): Safari 18.6 on macOS 15.7.8 x86_64 and Safari 27.0 on
// macOS 26.6 arm64. Wire facts the specs reproduce exactly (extension
// order included):
//
//		eaea, server_name, extended_master_secret, renegotiation_info,
//		supported_groups, ec_point_formats, alpn, status_request,
//		signature_algorithms, sct, key_share, psk_key_exchange_modes,
//		supported_versions, compress_certificate, <tail>
//
//	  - 20 cipher suites (Apple's legacy tail) — JA4 t13d2014h2 / t13d2013h2
//	  - Safari's signature_algorithms list duplicates rsa_pss_rsae_sha384
//	    (…,0503,0805,0805,0501,…) — do not deduplicate
//	  - Safari 18.6 pads the hello with extension 0x0015 and keeps TLS
//	    1.1/1.0 in supported_versions; Safari 27 drops padding (the ML-KEM
//	    key share alone pushes the hello to ~1540 bytes) and offers only
//	    TLS 1.3/1.2
//	  - Safari 27 offers X25519MLKEM768 (0x11ec) first among groups and
//	    sends both key shares
//	  - GREASE values are random per connection in real Safari; the specs
//	    emit fixed GREASE-pattern values, which JA4 ignores and JA3 keeps
//	    stable
//
// Safari never sends sec-ch-ua client hints; the Safari profiles leave
// them empty and Headers() omits them.
const safariClient = "safari"

// HelloSafari_18_6 selects the Safari 18.6 (macOS 15.7.8) hello.
var HelloSafari_18_6 = utls.ClientHelloID{Client: safariClient, Version: "18.6"}

// HelloSafari_27_0 selects the Safari 27.0 (macOS 26.6) hello.
var HelloSafari_27_0 = utls.ClientHelloID{Client: safariClient, Version: "27.0"}

// SafariMacOS mimics current Safari on macOS (27.0, macOS 26.6).
var SafariMacOS = Profile{
	name:           "SafariMacOS",
	userAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15",
	acceptLanguage: "ru",
	clientHelloID:  HelloSafari_27_0,
}

// SafariMacOS186 mimics Safari 18.6 on macOS 15.7.8.
var SafariMacOS186 = Profile{
	name:           "SafariMacOS186",
	userAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
	acceptLanguage: "ru",
	clientHelloID:  HelloSafari_18_6,
}

var safariCipherSuites = []uint16{
	0x1301, 0x1302, 0x1303,
	0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
	0xc00a, 0xc009, 0xc014, 0xc013,
	0x009d, 0x009c, 0x0035, 0x002f,
	0xc008, 0xc012, 0x000a,
}

// safariSignatureAlgorithms is Safari's list verbatim, including the
// duplicated rsa_pss_rsae_sha384 (0x0805) entry.
var safariSignatureAlgorithms = []utls.SignatureScheme{
	0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
}

func safariHelloSpec(version string) utls.ClientHelloSpec {
	var (
		groups    *utls.SupportedCurvesExtension
		keyShares *utls.KeyShareExtension
		suppVers  *utls.SupportedVersionsExtension
		tail      []utls.TLSExtension
	)
	if version == "27.0" {
		groups = &utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			0xfafa, utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
		}}
		keyShares = &utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.X25519MLKEM768}, {Group: utls.X25519},
		}}
		suppVers = &utls.SupportedVersionsExtension{Versions: []uint16{0x9a9a, utls.VersionTLS13, utls.VersionTLS12}}
		tail = []utls.TLSExtension{
			&utls.GenericExtension{Id: 0xdada}, // trailing GREASE extension
		}
	} else {
		groups = &utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			0x1a1a, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
		}}
		keyShares = &utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}}
		suppVers = &utls.SupportedVersionsExtension{Versions: []uint16{
			0xfafa, utls.VersionTLS13, utls.VersionTLS12, 0x0302, 0x0301,
		}}
		tail = []utls.TLSExtension{
			&utls.GenericExtension{Id: 0x0a0a, Data: []byte{0x00}}, // GREASE extension with payload
			// Safari 18.6 pads the hello to ~517 bytes; JA4/JA3 hash the
			// extension's presence, not its length, so fixed zeros are safe.
			&utls.GenericExtension{Id: 0x0015, Data: make([]byte, 196)},
			// uTLS v1.8 ApplyPreset drops the spec's last extension; this
			// sacrificial GREASE placeholder shields the padding.
			&utls.GenericExtension{Id: 0xfafa},
		}
	}

	extensions := []utls.TLSExtension{
		&utls.GenericExtension{Id: 0xeaea}, // Safari's leading GREASE extension
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{},
		groups,
		&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: safariSignatureAlgorithms},
		&utls.SCTExtension{},
		keyShares,
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		suppVers,
		&utls.GenericExtension{Id: 0x001b, Data: []byte{0x02, 0x00, 0x01}}, // compress_certificate: zlib only
	}
	extensions = append(extensions, tail...)

	return utls.ClientHelloSpec{
		CipherSuites:       append([]uint16{utls.GREASE_PLACEHOLDER}, safariCipherSuites...),
		CompressionMethods: []byte{0},
		Extensions:         extensions,
	}
}
