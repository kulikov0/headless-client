package headless

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kulikov0/headless-client/internal/dtls"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/selfsign"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/extension/dtls13"
	"github.com/kulikov0/headless-client/internal/dtls/pkg/protocol/handshake"
)

const vendorHandshakeTimeout = 10 * time.Second

type recordingPacketConn struct {
	net.PacketConn
	mutex sync.Mutex
	sizes []int
}

func (conn *recordingPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	conn.mutex.Lock()
	conn.sizes = append(conn.sizes, len(payload))
	conn.mutex.Unlock()

	return conn.PacketConn.WriteTo(payload, address)
}

func (conn *recordingPacketConn) writtenSizes() []int {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return slices.Clone(conn.sizes)
}

type dtlsLoopbackResult struct {
	clientHello         handshake.MessageClientHello
	serverHello         handshake.MessageServerHello
	serverHelloHooked   bool
	clientDatagramSizes []int
}

func runDTLSLoopback(
	t *testing.T,
	clientOptions []dtls.ClientOption,
	serverOptions []dtls.ServerOption,
) dtlsLoopbackResult {
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

	rawClientPacketConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer rawClientPacketConnection.Close()
	clientPacketConnection := &recordingPacketConn{PacketConn: rawClientPacketConnection}

	handshakeContext, cancel := context.WithTimeout(context.Background(), vendorHandshakeTimeout)
	defer cancel()

	capturedServerHello := make(chan handshake.MessageServerHello, 4)
	serverDone := make(chan error, 1)
	go func() {
		options := []dtls.ServerOption{
			dtls.WithCertificates(certificate),
			dtls.WithServerHelloMessageHook(func(serverHello handshake.MessageServerHello) handshake.Message {
				select {
				case capturedServerHello <- serverHello:
				default:
				}

				return &serverHello
			}),
		}
		connection, serverErr := dtls.ServerWithOptions(serverPacketConnection, clientPacketConnection.LocalAddr(),
			append(options, serverOptions...)...,
		)
		if serverErr != nil {
			serverDone <- serverErr

			return
		}
		defer connection.Close()
		serverDone <- connection.HandshakeContext(handshakeContext)
	}()

	capturedClientHello := make(chan handshake.MessageClientHello, 4)
	clientDone := make(chan error, 1)
	go func() {
		options := []dtls.ClientOption{
			dtls.WithInsecureSkipVerify(true),
			dtls.WithClientHelloMessageHook(func(clientHello handshake.MessageClientHello) handshake.Message {
				select {
				case capturedClientHello <- clientHello:
				default:
				}

				return &clientHello
			}),
		}
		connection, clientErr := dtls.ClientWithOptions(clientPacketConnection, serverPacketConnection.LocalAddr(),
			append(options, clientOptions...)...,
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

	result := dtlsLoopbackResult{clientDatagramSizes: clientPacketConnection.writtenSizes()}
	select {
	case result.clientHello = <-capturedClientHello:
	default:
		t.Fatal("the handshake completed without a client hello reaching the hook")
	}
	select {
	case result.serverHello = <-capturedServerHello:
		result.serverHelloHooked = true
	default:
	}

	return result
}

func dtlsLoopbackClientHello(t *testing.T, serverOptions ...dtls.ServerOption) handshake.MessageClientHello {
	t.Helper()

	return runDTLSLoopback(t, nil, serverOptions).clientHello
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

func TestVendoredDTLSCallsTheServerHelloHookOnVersion13(t *testing.T) {
	result := runDTLSLoopback(t, nil, nil)

	if !result.serverHelloHooked {
		t.Fatal("the server hello hook never ran, so dtls-serverhello13-hook.patch was lost and every 1.3 server hello ships the pion extension order")
	}
	if !offersExtension(result.serverHello.Extensions, extension.TypeSupportedVersions) {
		t.Fatalf("the hooked server hello carries %v, a 1.3 server hello carries supported_versions; the loopback negotiated 1.2 and this guard proved nothing", serverHelloExtensionOrder(&result.serverHello))
	}
}

func TestVendoredDTLSFillsTheHandshakeDatagramToTheMTU(t *testing.T) {
	const maximumTransmissionUnit = 200

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("self signed certificate: %v", err)
	}
	cases := []struct {
		name          string
		clientOptions []dtls.ClientOption
		serverOptions []dtls.ServerOption
	}{
		{
			"plaintext client hello",
			[]dtls.ClientOption{dtls.WithMTU(maximumTransmissionUnit)},
			nil,
		},
		{
			"encrypted client certificate",
			[]dtls.ClientOption{dtls.WithMTU(maximumTransmissionUnit), dtls.WithCertificates(certificate)},
			[]dtls.ServerOption{dtls.WithClientAuth(dtls.RequireAnyClientCert)},
		},
	}
	for _, testCase := range cases {
		result := runDTLSLoopback(t, testCase.clientOptions, testCase.serverOptions)

		for _, size := range result.clientDatagramSizes {
			if size > maximumTransmissionUnit {
				t.Fatalf("%s: a client datagram is %d bytes against an MTU of %d, so the record overhead was added on top of a full fragment and dtls-handshake-fragment-mtu.patch was lost; sizes %v", testCase.name, size, maximumTransmissionUnit, result.clientDatagramSizes)
			}
		}
		if !slices.Contains(result.clientDatagramSizes, maximumTransmissionUnit) {
			t.Fatalf("%s: no client datagram reached the MTU of %d, chrome sizes the first fragment so the datagram is exactly the MTU; sizes %v", testCase.name, maximumTransmissionUnit, result.clientDatagramSizes)
		}
	}
}

func TestVendoredDTLSMimicryEmitsTheChromeExtensionSet(t *testing.T) {
	profile := ChromeWindows.WithDTLS13Mimicry()
	want := []uint16{10, 11, 13, 14, 23, 43, 45, 51, 65281}

	clientPacketConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPacketConnection.Close()
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silent listen: %v", err)
	}
	defer silent.Close()

	captured := make(chan []uint16, 4)
	handshakeContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	connection, err := dtls.ClientWithOptions(clientPacketConnection, silent.LocalAddr(),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithClientHelloMessageHook(func(clientHello handshake.MessageClientHello) handshake.Message {
			hooked := profile.dtls13MimicHook(clientHello)
			if message, ok := hooked.(*handshake.MessageClientHello); ok {
				types := make([]uint16, 0, len(message.Extensions))
				for _, value := range message.Extensions {
					types = append(types, uint16(value.ExtensionType()))
				}
				select {
				case captured <- types:
				default:
				}
			}

			return hooked
		}),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer connection.Close()
	_ = connection.HandshakeContext(handshakeContext)

	select {
	case types := <-captured:
		slices.Sort(types)
		if !slices.Equal(types, want) {
			t.Fatalf("mimicry emitted %v, chrome sends %v in thirteen measured handshakes", types, want)
		}
	default:
		t.Fatal("no client hello reached the mimicry hook")
	}
}
