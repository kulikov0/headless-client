package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/kulikov0/headless-client/stand/internal/wire"
)

const (
	dtlsHandshakeContentType = 22
	quicLongHeaderBit        = 0x80
)

type observation struct {
	hello     *wire.Hello
	target    string
	transport string
}

type roleCapture struct {
	name         string
	path         string
	observations []observation
	tcpFlows     int
	udpDatagrams int
}

func (c *roleCapture) observe(hello *wire.Hello, target, transport string) {
	if hello == nil {
		return
	}
	if hello.ServerName != "" {
		target = hello.ServerName
	}
	c.observations = append(c.observations, observation{hello: hello, target: target, transport: transport})
}

func readCapture(name, path string) (*roleCapture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, err
	}

	capture := &roleCapture{name: name, path: path}
	assembler := wire.NewAssembler()

	source := gopacket.NewPacketSource(reader, reader.LinkType())
	for packet := range source.Packets() {
		network := packet.NetworkLayer()
		transport := packet.TransportLayer()
		if network == nil || transport == nil {
			continue
		}
		payload := transport.LayerPayload()
		if len(payload) == 0 {
			continue
		}
		flowKey := network.NetworkFlow().String() + "/" + transport.TransportFlow().String()
		target := flowTarget(network, transport)

		switch transport.(type) {
		case *layers.TCP:
			hello, err := assembler.AssembleTCP(flowKey, payload)
			if err == nil {
				capture.observe(hello, target, "tls")
			}

		case *layers.UDP:
			capture.udpDatagrams++
			if payload[0] == dtlsHandshakeContentType {
				hello, err := assembler.AssembleDTLS(flowKey, payload)
				if err == nil {
					capture.observe(hello, target, "dtls")
				}
				continue
			}
			if payload[0]&quicLongHeaderBit == 0 {
				continue
			}
			_, hello := assembler.AssembleQUIC(payload)
			capture.observe(hello, target, "quic")
		}
	}
	capture.tcpFlows = assembler.Flows()

	return capture, nil
}

func flowTarget(network gopacket.NetworkLayer, transport gopacket.TransportLayer) string {
	_, destinationAddress := network.NetworkFlow().Endpoints()
	_, destinationPort := transport.TransportFlow().Endpoints()

	return destinationAddress.String() + ":" + destinationPort.String()
}

func expandCaptures(argument string) ([]string, error) {
	info, err := os.Stat(argument)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{argument}, nil
	}
	matches, err := filepath.Glob(filepath.Join(argument, "*.pcap"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no pcap files in %s", argument)
	}

	return matches, nil
}

func roleName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}
