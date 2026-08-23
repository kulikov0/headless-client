package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Captured 2026-08-01 from pion/webrtc v4.2.9 + pion/dtls v3.1.2
const pionDTLSClientHelloHex = "16fefd0000000000000000007e" +
	"010000720000000000000072" +
	"fefd" +
	"6a6e150c543ac89a1f41c1013846f7513902ae203f6fe8fb50e5114f90c9ea9f" +
	"00" +
	"00" +
	"000c" + "c02bc02fc00ac014c02cc030" +
	"01" + "00" +
	"003c" +
	"000d0010000e0403050306030807040105010601" +
	"ff01000100" +
	"000a00080006001d00170018" +
	"000b00020100" +
	"000e0009000600080007000100" +
	"00170000"

// The rule published for the Russian DPI filter: this pattern at this offset
// from the start of the DTLS record
var (
	tspuSignature = []byte{0x1d, 0x00, 0x17, 0x00, 0x18}
	tspuOffset    = 0x6f
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return raw
}

func TestParsePionDTLSClientHello(t *testing.T) {
	record := mustDecode(t, pionDTLSClientHelloHex)
	if len(record) != 139 {
		t.Fatalf("fixture length = %d, want 139", len(record))
	}

	hello, err := ParseHello(record)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}

	if hello.Kind != HelloDTLSClient {
		t.Errorf("Kind = %q, want %q", hello.Kind, HelloDTLSClient)
	}
	if hello.RecordVersion != versionDTLS12 {
		t.Errorf("RecordVersion = %#04x, want %#04x", hello.RecordVersion, versionDTLS12)
	}
	if hello.MessageSeq != 0 {
		t.Errorf("MessageSeq = %d, want 0", hello.MessageSeq)
	}
	if hello.CookieLen != 0 {
		t.Errorf("CookieLen = %d, want 0", hello.CookieLen)
	}

	wantSuites := []uint16{0xc02b, 0xc02f, 0xc00a, 0xc014, 0xc02c, 0xc030}
	if !equalUint16(hello.CipherSuites, wantSuites) {
		t.Errorf("CipherSuites = %#04x, want %#04x", hello.CipherSuites, wantSuites)
	}

	wantExtensions := []uint16{0x000d, 0xff01, 0x000a, 0x000b, 0x000e, 0x0017}
	if !equalUint16(hello.ExtensionTypes(), wantExtensions) {
		t.Errorf("extension order = %#04x, want %#04x", hello.ExtensionTypes(), wantExtensions)
	}

	wantGroups := []uint16{0x001d, 0x0017, 0x0018}
	if !equalUint16(hello.SupportedGroups, wantGroups) {
		t.Errorf("SupportedGroups = %#04x, want %#04x", hello.SupportedGroups, wantGroups)
	}

	wantProfiles := []uint16{0x0008, 0x0007, 0x0001}
	if !equalUint16(hello.UseSRTPProfiles, wantProfiles) {
		t.Errorf("UseSRTPProfiles = %#04x, want %#04x", hello.UseSRTPProfiles, wantProfiles)
	}
}

func TestPionMatchesPublishedDPIRule(t *testing.T) {
	record := mustDecode(t, pionDTLSClientHelloHex)

	hello, err := ParseHello(record)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}

	groupsOffset := hello.ExtensionOffset(extSupportedGroups)
	if groupsOffset != 0x68 {
		t.Fatalf("supported_groups offset = %#x, want 0x68", groupsOffset)
	}

	if got := record[tspuOffset : tspuOffset+len(tspuSignature)]; !bytes.Equal(got, tspuSignature) {
		t.Fatalf("bytes at %#x = % x, want % x", tspuOffset, got, tspuSignature)
	}
	t.Logf("pion matches the published signature % x at offset %#x", tspuSignature, tspuOffset)
}

func TestParseRejectsFragmentedDTLS(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"later fragment":  func(record []byte) { record[21] = 0x10 },
		"partial message": func(record []byte) { record[24] = 0x30 },
	} {
		record := mustDecode(t, pionDTLSClientHelloHex)
		mutate(record)
		if _, err := ParseHello(record); !errors.Is(err, ErrFragmented) {
			t.Errorf("%s: err = %v, want ErrFragmented", name, err)
		}
	}
}

func dtlsFragmentRecord(part []byte, offset, total uint32) []byte {
	record := []byte{0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0}
	record = append(record, byte((12+len(part))>>8), byte(12+len(part)))
	record = append(record, handshakeClientHello)
	record = append(record, byte(total>>16), byte(total>>8), byte(total))
	record = append(record, 0, 0)
	record = append(record, byte(offset>>16), byte(offset>>8), byte(offset))
	record = append(record, byte(len(part)>>16), byte(len(part)>>8), byte(len(part)))
	return append(record, part...)
}

func TestAssemblesFragmentedDTLSClientHello(t *testing.T) {
	full := mustDecode(t, pionDTLSClientHelloHex)
	body := full[dtlsRecordHeaderLen+dtlsHandshakeHeaderLen:]
	const split = 60

	assembler := NewAssembler()
	first := dtlsFragmentRecord(body[:split], 0, uint32(len(body)))
	second := dtlsFragmentRecord(body[split:], split, uint32(len(body)))

	if hello, err := assembler.AssembleDTLS("flow", first); hello != nil || err != nil {
		t.Fatalf("first fragment: hello=%v err=%v, want nothing yet", hello, err)
	}
	hello, err := assembler.AssembleDTLS("flow", second)
	if err != nil {
		t.Fatalf("second fragment: %v", err)
	}
	if hello == nil {
		t.Fatal("second fragment did not complete the message")
	}

	whole, err := ParseHello(full)
	if err != nil {
		t.Fatalf("unfragmented reference: %v", err)
	}
	if !equalUint16(hello.ExtensionTypes(), whole.ExtensionTypes()) {
		t.Errorf("extensions = %#04x, want %#04x", hello.ExtensionTypes(), whole.ExtensionTypes())
	}
	if !equalUint16(hello.CipherSuites, whole.CipherSuites) {
		t.Errorf("ciphers = %#04x, want %#04x", hello.CipherSuites, whole.CipherSuites)
	}
	if got := hello.ExtensionOffset(extSupportedGroups); got != whole.ExtensionOffset(extSupportedGroups) {
		t.Errorf("supported_groups offset = %#x, want %#x", got, whole.ExtensionOffset(extSupportedGroups))
	}
	if len(assembler.dtlsFrags) != 0 {
		t.Errorf("assembly left %d pending entries", len(assembler.dtlsFrags))
	}
}

func TestParseRejectsNonHandshake(t *testing.T) {
	for name, record := range map[string][]byte{
		"application data": {0x17, 0xfe, 0xfd, 0x00, 0x00},
		"too short":        {0x16, 0xfe},
		"handshake but not a hello": append(
			mustDecode(t, "16fefd0000000000000000000c"),
			0x0b, 0x00, 0x00, 0x00,
		),
	} {
		if _, err := ParseHello(record); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func equalUint16(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
