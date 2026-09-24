package headless

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
) // safariExtensionIDs maps the spec's typed extensions back to the wire
// extension IDs so tests can assert the exact captured order.
func safariExtensionIDs(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	ids := make([]uint16, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		switch typed := ext.(type) {
		case *utls.GenericExtension:
			ids = append(ids, typed.Id)
		case *utls.SNIExtension:
			ids = append(ids, 0x0000)
		case *utls.ExtendedMasterSecretExtension:
			ids = append(ids, 0x0017)
		case *utls.RenegotiationInfoExtension:
			ids = append(ids, 0xff01)
		case *utls.SupportedCurvesExtension:
			ids = append(ids, 0x000a)
		case *utls.SupportedPointsExtension:
			ids = append(ids, 0x000b)
		case *utls.ALPNExtension:
			ids = append(ids, 0x0010)
		case *utls.StatusRequestExtension:
			ids = append(ids, 0x0005)
		case *utls.SignatureAlgorithmsExtension:
			ids = append(ids, 0x000d)
		case *utls.SCTExtension:
			ids = append(ids, 0x0012)
		case *utls.KeyShareExtension:
			ids = append(ids, 0x0033)
		case *utls.PSKKeyExchangeModesExtension:
			ids = append(ids, 0x002d)
		case *utls.SupportedVersionsExtension:
			ids = append(ids, 0x002b)
		case *utls.UtlsPaddingExtension:
			ids = append(ids, 0x0015)
		default:
			t.Fatalf("unmapped extension type %T in spec", ext)
		}
	}
	return ids
}

func safariVersions(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	for _, ext := range spec.Extensions {
		if typed, ok := ext.(*utls.SupportedVersionsExtension); ok {
			return typed.Versions
		}
	}
	t.Fatal("no supported_versions extension")
	return nil
}

func TestSafari186SpecShape(t *testing.T) {
	spec, err := SafariMacOS186.clientHelloSpec(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []uint16{
		0xeaea, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
		0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0a0a, 0x0015,
		0xfafa, // sacrificial GREASE: shields padding from the ApplyPreset last-extension drop
	}
	if got := safariExtensionIDs(t, spec); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("extension order mismatch:\n got % x\nwant % x", got, wantIDs)
	}
	if len(spec.CipherSuites) != len(safariCipherSuites)+1 || spec.CipherSuites[0] != utls.GREASE_PLACEHOLDER {
		t.Fatalf("cipher suites wrong: %v", spec.CipherSuites)
	}
	for _, ext := range spec.Extensions {
		if typed, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			algs := typed.SupportedSignatureAlgorithms
			if len(algs) != 10 {
				t.Fatalf("want 10 signature algorithms, got %d", len(algs))
			}
			if algs[4] != 0x0805 || algs[5] != 0x0805 {
				t.Fatalf("safari duplicates rsa_pss_rsae_sha384 at [4],[5]: %v", algs)
			}
		}
	}
	wantVersions := []uint16{0xfafa, 0x0304, 0x0303, 0x0302, 0x0301}
	if got := safariVersions(t, spec); !reflect.DeepEqual(got, wantVersions) {
		t.Fatalf("supported_versions mismatch: got % x want % x", got, wantVersions)
	}
}

func TestSafari270SpecShape(t *testing.T) {
	spec, err := SafariMacOS.clientHelloSpec(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []uint16{
		0xeaea, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
		0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0xdada,
	}
	if got := safariExtensionIDs(t, spec); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("extension order mismatch:\n got % x\nwant % x", got, wantIDs)
	}
	wantVersions := []uint16{0x9a9a, 0x0304, 0x0303}
	if got := safariVersions(t, spec); !reflect.DeepEqual(got, wantVersions) {
		t.Fatalf("supported_versions mismatch: got % x want % x", got, wantVersions)
	}
	for _, ext := range spec.Extensions {
		switch typed := ext.(type) {
		case *utls.SupportedCurvesExtension:
			if typed.Curves[1] != utls.X25519MLKEM768 || typed.Curves[2] != utls.X25519 {
				t.Fatalf("safari 27 offers ML-KEM then x25519: %v", typed.Curves)
			}
		case *utls.KeyShareExtension:
			groups := make([]utls.CurveID, len(typed.KeyShares))
			for i, share := range typed.KeyShares {
				groups[i] = share.Group
			}
			if !reflect.DeepEqual(groups, []utls.CurveID{utls.X25519MLKEM768, utls.X25519}) {
				t.Fatalf("key shares must cover both offered PQ+classic groups: %v", groups)
			}
		}
	}
}

func TestSafariHeadersHaveNoClientHints(t *testing.T) {
	for _, profile := range []Profile{SafariMacOS, SafariMacOS186} {
		header := profile.Headers(DestDocument)
		for _, hint := range []string{"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"} {
			if _, present := header[hint]; present {
				t.Fatalf("%s must not send %s", profile.Name(), hint)
			}
		}
	}
	if SafariMacOS.userAgent == "" {
		t.Fatal("empty user agent")
	}
}

// TestSafari186WireHello captures the actual ClientHello bytes on loopback
// and asserts the extension set — this is what the fp receiver's JA4 sees.
func TestSafari186WireHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		got <- buf[:n]
	}()

	spec, err := SafariMacOS186.clientHelloSpec(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	uConn := utls.UClient(raw, &utls.Config{ServerName: "test.auto-gram.ru", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	_ = uConn.HandshakeContext(context.Background()) // server closes; hello is already on the wire

	select {
	case buf := <-got:
		if len(buf) == 0 {
			t.Fatal("no ClientHello captured")
		}
		ids, total := parseClientHelloExtensionIDs(t, buf)
		t.Logf("hello record %d bytes, extensions: % x", total, ids)
		if !reflect.DeepEqual(ids, []uint16{
			0xeaea, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
			0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0a0a, 0x0015,
			0xfafa,
		}) {
			t.Fatalf("wire extension order mismatch: % x", ids)
		}
		hasPadding := false
		for _, id := range ids {
			if id == 0x0015 {
				hasPadding = true
			}
		}
		if !hasPadding {
			t.Fatalf("Safari 18.6 hello must carry padding 0x0015 (got % x)", ids)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello")
	}
}

// parseClientHelloExtensionIDs walks a TLS record containing a ClientHello
// and returns the extension IDs plus the total record length.
func parseClientHelloExtensionIDs(t *testing.T, buf []byte) ([]uint16, int) {
	t.Helper()
	if buf[0] != 0x16 {
		t.Fatalf("not a handshake record: % x", buf[:3])
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	hs := buf[5:]
	if hs[0] != 0x01 {
		t.Fatalf("not a ClientHello: % x", hs[:4])
	}
	p := 4 // handshake header
	p += 2 // client version
	p += 32
	p += 1 + int(hs[p])
	p += 2 + int(hs[p])<<8 + int(hs[p+1])
	p += 1 + int(hs[p])
	extLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	end := p + extLen
	var ids []uint16
	for p+4 <= end {
		id := uint16(hs[p])<<8 | uint16(hs[p+1])
		l := int(hs[p+2])<<8 | int(hs[p+3])
		ids = append(ids, id)
		p += 4 + l
	}
	return ids, 5 + recLen
}
