package wire

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func loadHexFixture(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	raw, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return raw
}

// Captured 2026-08-02 from Chrome 151
func TestParseChromeQUICInitial(t *testing.T) {
	datagram := loadHexFixture(t, "quic_v1_initial_chrome.hex")

	initial, err := ParseQUICInitial(datagram)
	if err != nil {
		t.Fatalf("ParseQUICInitial: %v", err)
	}
	if got := hex.EncodeToString(initial.DestConnID); got != "a95d05bcce4e6b4c" {
		t.Errorf("DestConnID = %s, want a95d05bcce4e6b4c", got)
	}
	if initial.PacketNum != 1 {
		t.Errorf("PacketNum = %d, want 1", initial.PacketNum)
	}
	if len(initial.Crypto) < 2 {
		t.Fatalf("crypto chunks = %d, chrome splits the hello across several", len(initial.Crypto))
	}
	handshake := AssembleCrypto(initial.Crypto)
	if len(handshake) == 0 {
		t.Fatal("crypto stream did not assemble")
	}

	record, err := CryptoRecord(handshake)
	if err != nil {
		t.Fatalf("CryptoRecord: %v", err)
	}
	hello, err := ParseHello(record)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}

	wantSuites := []uint16{0x1301, 0x1302, 0x1303}
	if !equalUint16(hello.CipherSuites, wantSuites) {
		t.Errorf("CipherSuites = %#04x, want %#04x", hello.CipherSuites, wantSuites)
	}
	wantExtensions := []uint16{0, 57, 51, 10, 17613, 43, 13, 16, 27, 45}
	if !equalUint16(hello.ExtensionTypes(), wantExtensions) {
		t.Errorf("extension order = %v, want %v", hello.ExtensionTypes(), wantExtensions)
	}

	wantParams := []uint64{4, 17, 7, 5, 2452502694429132963, 3, 1, 8, 6, 15, 9, 32}
	gotParams := make([]uint64, len(hello.QUICTransportParams))
	grease := 0
	for i, param := range hello.QUICTransportParams {
		gotParams[i] = param.ID
		if param.IsGREASE() {
			grease++
		}
	}
	if len(gotParams) != len(wantParams) {
		t.Fatalf("transport params = %v, want %v", gotParams, wantParams)
	}
	for i := range wantParams {
		if gotParams[i] != wantParams[i] {
			t.Fatalf("transport params = %v, want %v", gotParams, wantParams)
		}
	}
	if grease != 1 {
		t.Errorf("grease params = %d, want 1", grease)
	}
}

func TestParseQUICRejectsOtherVersions(t *testing.T) {
	datagram := loadHexFixture(t, "quic_v1_initial_chrome.hex")
	datagram[4] = 0x02

	if _, err := ParseQUICInitial(datagram); err == nil {
		t.Fatal("expected an error for a non-v1 version")
	}
}
