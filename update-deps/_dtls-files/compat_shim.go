package dtls

import (
	"net"

	cryptosuite "github.com/kulikov0/headless-client/internal/dtls/pkg/crypto/ciphersuite"
)

type (
	CipherSuiteID = cryptosuite.ID
	CipherSuite   = cryptosuite.Suite
)

func ClientWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ClientOption) (*Conn, error) {
	return Client(conn, rAddr, opts...)
}

func ServerWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ServerOption) (*Conn, error) {
	return Server(conn, rAddr, opts...)
}
