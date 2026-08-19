package dtls

import (
	"net"

	"github.com/pion/logging"
)

type Config struct {
	ServerName         string
	InsecureSkipVerify bool
	LoggerFactory      logging.LoggerFactory
}

func (c *Config) clientOptions() []ClientOption {
	if c == nil {
		return nil
	}
	var opts []ClientOption
	if c.ServerName != "" {
		opts = append(opts, WithServerName(c.ServerName))
	}
	if c.InsecureSkipVerify {
		opts = append(opts, WithInsecureSkipVerify(true))
	}
	if c.LoggerFactory != nil {
		opts = append(opts, WithLoggerFactory(c.LoggerFactory))
	}
	return opts
}

func (c *Config) serverOptions() []ServerOption {
	if c == nil {
		return nil
	}
	var opts []ServerOption
	if c.LoggerFactory != nil {
		opts = append(opts, WithLoggerFactory(c.LoggerFactory))
	}
	return opts
}

func Client(conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	return ClientWithOptions(conn, rAddr, config.clientOptions()...)
}

func Server(conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	return ServerWithOptions(conn, rAddr, config.serverOptions()...)
}
