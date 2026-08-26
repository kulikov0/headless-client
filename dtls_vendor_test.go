package headless

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/kulikov0/headless-client/internal/dtls"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/selfsign"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/handshake"
)

const vendorHandshakeTimeout = 10 * time.Second

func dtlsLoopbackClientHello(t *testing.T, serverOptions ...dtls.ServerOption) handshake.MessageClientHello {
	t.Helper()

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("self signed certificate: %v", err)
	}

	serverPacketConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPacketConnection.Close()

	clientPacketConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPacketConnection.Close()

	handshakeContext, cancel := context.WithTimeout(context.Background(), vendorHandshakeTimeout)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		connection, serverErr := dtls.ServerWithOptions(serverPacketConnection, clientPacketConnection.LocalAddr(),
			append([]dtls.ServerOption{dtls.WithCertificates(certificate)}, serverOptions...)...,
		)
		if serverErr != nil {
			serverDone <- serverErr

			return
		}
		defer connection.Close()
		serverDone <- connection.HandshakeContext(handshakeContext)
	}()

	captured := make(chan handshake.MessageClientHello, 4)
	clientDone := make(chan error, 1)
	go func() {
		connection, clientErr := dtls.ClientWithOptions(clientPacketConnection, serverPacketConnection.LocalAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithClientHelloMessageHook(func(clientHello handshake.MessageClientHello) handshake.Message {
				select {
				case captured <- clientHello:
				default:
				}

				return &clientHello
			}),
		)
		if clientErr != nil {
			clientDone <- clientErr

			return
		}
		defer connection.Close()
		clientDone <- connection.HandshakeContext(handshakeContext)
	}()

	for _, side := range []struct {
		name string
		done chan error
	}{{"server", serverDone}, {"client", clientDone}} {
		select {
		case sideErr := <-side.done:
			if sideErr != nil {
				t.Fatalf("%s handshake: %v; a deadline here means the dual-stack server path never primed its receiver, so dtls-dualstack-server-prime.patch was lost", side.name, sideErr)
			}
		case <-time.After(2 * vendorHandshakeTimeout):
			t.Fatalf("%s never returned from the handshake", side.name)
		}
	}

	select {
	case clientHello := <-captured:
		return clientHello
	default:
		t.Fatal("the handshake completed without a client hello reaching the hook")
	}

	return handshake.MessageClientHello{}
}

func TestVendoredDTLSCompletesADualStackHandshake(t *testing.T) {
	dtlsLoopbackClientHello(t)
}

func TestVendoredDTLSOffersBothProtocolVersions(t *testing.T) {
	clientHello := dtlsLoopbackClientHello(t)

	var offered []protocol.Version
	for _, value := range clientHello.Extensions {
		switch versions := value.(type) {
		case *dtls13.OfferedVersions:
			offered = versions.Versions
		case dtls13.OfferedVersions:
			offered = versions.Versions
		}
	}

	want := []protocol.Version{protocol.Version1_3, protocol.Version1_2}
	if !slices.Equal(offered, want) {
		t.Fatalf("supported_versions offers %v, chrome offers %v; an unset maximum version fell back to 1.2, so dtls-default-version.patch was lost", offered, want)
	}
}

func TestVendoredDTLSFallsBackToVersion12(t *testing.T) {
	dtlsLoopbackClientHello(t, dtls.WithMaxVersion(protocol.Version1_2))
}
