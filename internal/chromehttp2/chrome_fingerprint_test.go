package http2

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type capturedHandshake struct {
	settings            []Setting
	connWindowIncrement uint32
}

func readClientHandshake(serverConn net.Conn) (capturedHandshake, error) {
	var captured capturedHandshake
	preface := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(serverConn, preface); err != nil {
		return captured, fmt.Errorf("read preface: %w", err)
	}
	framer := NewFramer(serverConn, serverConn)
	settingsFrame, err := framer.ReadFrame()
	if err != nil {
		return captured, fmt.Errorf("read settings frame: %w", err)
	}
	settings, ok := settingsFrame.(*SettingsFrame)
	if !ok {
		return captured, fmt.Errorf("first frame is %T, want *SettingsFrame", settingsFrame)
	}
	settings.ForeachSetting(func(setting Setting) error {
		captured.settings = append(captured.settings, setting)
		return nil
	})
	windowFrame, err := framer.ReadFrame()
	if err != nil {
		return captured, fmt.Errorf("read window update frame: %w", err)
	}
	windowUpdate, ok := windowFrame.(*WindowUpdateFrame)
	if !ok {
		return captured, fmt.Errorf("second frame is %T, want *WindowUpdateFrame", windowFrame)
	}
	captured.connWindowIncrement = windowUpdate.Increment
	return captured, nil
}

func TestChromeH2SettingsFingerprint(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	resultChan := make(chan capturedHandshake, 1)
	errorChan := make(chan error, 1)
	go func() {
		captured, err := readClientHandshake(serverConn)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- captured
	}()

	transport := &Transport{}
	if _, err := transport.NewClientConn(clientConn); err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	select {
	case err := <-errorChan:
		t.Fatalf("server read: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for client handshake")
	case captured := <-resultChan:
		wantSettings := []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingInitialWindowSize, Val: 6291456},
			{ID: SettingMaxHeaderListSize, Val: 262144},
		}
		if fmt.Sprint(captured.settings) != fmt.Sprint(wantSettings) {
			t.Fatalf("SETTINGS = %v, want %v", captured.settings, wantSettings)
		}
		if captured.connWindowIncrement != 15663105 {
			t.Fatalf("connection WINDOW_UPDATE increment = %d, want 15663105", captured.connWindowIncrement)
		}
	}
}
