package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	headless "github.com/kulikov0/headless-client"
	"github.com/kulikov0/headless-client/quic"
	"github.com/kulikov0/headless-client/quic/http3"
)

const (
	settingQPACKMaxTableCapacity      = 0x01
	settingMaxFieldSectionSize        = 0x06
	settingQPACKBlockedStreams        = 0x07
	settingDatagram                   = 0x33
	settingDatagramDraft04            = 0xffd277
	settingsEnableWebtransportDraft06 = 0x2b603742
)

func settingsForMode(mode string) (map[uint64]uint64, bool, error) {
	switch mode {
	case "current":
		return map[uint64]uint64{settingsEnableWebtransportDraft06: 1}, false, nil
	case "chrome":
		return map[uint64]uint64{
			settingQPACKMaxTableCapacity:      65536,
			settingMaxFieldSectionSize:        16384,
			settingQPACKBlockedStreams:        100,
			settingDatagram:                   1,
			settingDatagramDraft04:            1,
			settingsEnableWebtransportDraft06: 1,
		}, false, nil
	case "naive":
		return map[uint64]uint64{
			settingQPACKMaxTableCapacity:      65536,
			settingMaxFieldSectionSize:        16384,
			settingQPACKBlockedStreams:        100,
			settingDatagram:                   1,
			settingDatagramDraft04:            1,
			settingsEnableWebtransportDraft06: 1,
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown mode %q, want current, chrome or naive", mode)
}

func keyLogWriter() (*os.File, error) {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil, nil
	}

	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

func connectHeader(mode, origin string) http.Header {
	if mode == "current" {
		return http.Header{}
	}
	return headless.ChromeWindows.WebTransportConnectHeader(origin)
}

func sendConnect(ctx context.Context, control *http3.RawClientConn, serverName, address, requestPath string, header http.Header) (int, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	target, err := url.Parse("https://" + net.JoinHostPort(serverName, port) + requestPath)
	if err != nil {
		return 0, err
	}
	requestStr, err := control.OpenRequestStream(ctx)
	if err != nil {
		return 0, err
	}
	request := (&http.Request{
		Method: http.MethodConnect,
		Header: header,
		Proto:  "webtransport",
		Host:   target.Host,
		URL:    target,
	}).WithContext(ctx)
	if err := requestStr.SendRequestHeader(request); err != nil {
		return 0, err
	}
	response, err := requestStr.ReadResponse()
	if err != nil {
		return 0, err
	}

	return response.StatusCode, nil
}

func run(address, serverName, mode, requestPath, origin string) error {
	additionalSettings, enableDatagrams, err := settingsForMode(mode)
	if err != nil {
		return err
	}

	keyLogFile, err := keyLogWriter()
	if err != nil {
		return fmt.Errorf("keylog: %w", err)
	}
	var keyLog io.Writer
	if keyLogFile != nil {
		defer keyLogFile.Close()
		keyLog = keyLogFile
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if serverName == "" {
		serverName = host
	}

	conn, err := headless.ChromeWindows.DialQUIC(dialCtx, address, headless.QUICOptions{
		Transport:          headless.QUICWebTransport,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		EnableDatagrams:    true,
		KeepAlivePeriod:    15 * time.Second,
		MaxIdleTimeout:     30 * time.Second,
		KeyLogWriter:       keyLog,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	fmt.Printf("mode=%s handshake ok, alpn=%s\n", mode, conn.ConnectionState().TLS.NegotiatedProtocol)
	fmt.Printf("mode=%s peer supports quic datagrams: %t\n", mode, conn.ConnectionState().SupportsDatagrams)

	transport := &http3.Transport{
		EnableDatagrams:    enableDatagrams,
		SendGreaseFrames:   mode != "current",
		DisableCompression: mode != "current",
		AdditionalSettings: additionalSettings,
	}
	control := transport.NewRawClientConn(conn)
	defer transport.Close()

	go acceptUniStreams(conn, control)
	go acceptStreams(conn, control)

	select {
	case <-control.ReceivedSettings():
	case <-dialCtx.Done():
		return fmt.Errorf("no server settings: %w", dialCtx.Err())
	}
	settings := control.Settings()
	fmt.Printf("mode=%s server settings: datagram=%t extendedConnect=%t other=%v\n",
		mode, settings.EnableDatagrams, settings.EnableExtendedConnect, settings.Other)

	if requestPath != "" {
		if mode != "current" && origin == "" {
			return fmt.Errorf("mode %q sends a header block, so it needs an origin argument", mode)
		}
		status, err := sendConnect(dialCtx, control, serverName, address, requestPath, connectHeader(mode, origin))
		if err != nil {
			fmt.Printf("mode=%s connect failed: %v\n", mode, err)
		} else {
			fmt.Printf("mode=%s connect status %d\n", mode, status)
		}
	}

	deadline := time.After(10 * time.Second)
	select {
	case <-conn.Context().Done():
		return fmt.Errorf("connection closed after settings: %w", context.Cause(conn.Context()))
	case <-deadline:
	}
	fmt.Printf("mode=%s connection still alive 10s after settings\n", mode)

	return conn.CloseWithError(0, "")
}

func acceptUniStreams(conn *quic.Conn, control *http3.RawClientConn) {
	for {
		stream, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go control.HandleUnidirectionalStream(stream)
	}
}

func acceptStreams(conn *quic.Conn, control *http3.RawClientConn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go control.HandleBidirectionalStream(stream)
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: wtprobe <host:port> <servername> <current|chrome|naive> [path] [origin]")
		os.Exit(2)
	}
	requestPath := ""
	if len(os.Args) > 4 {
		requestPath = os.Args[4]
	}
	origin := ""
	if len(os.Args) > 5 {
		origin = os.Args[5]
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], requestPath, origin); err != nil {
		fmt.Fprintf(os.Stderr, "mode=%s FAILED: %v\n", os.Args[3], err)
		os.Exit(1)
	}
}
