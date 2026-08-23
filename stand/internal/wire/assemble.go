package wire

import (
	"encoding/hex"
	"fmt"
)

const maxFlowBuffer = 1 << 16

type tcpFlow struct {
	body []byte
	done bool
}

type dtlsAssembly struct {
	body   []byte
	filled []bool
}

type quicStream struct {
	chunks []QUICCryptoChunk
	done   bool
}

type Assembler struct {
	tcpFlows    map[string]*tcpFlow
	dtlsFrags   map[string]*dtlsAssembly
	quicStreams map[string]*quicStream
}

func NewAssembler() *Assembler {
	return &Assembler{
		tcpFlows:    map[string]*tcpFlow{},
		dtlsFrags:   map[string]*dtlsAssembly{},
		quicStreams: map[string]*quicStream{},
	}
}

func (a *Assembler) Flows() int {
	return len(a.tcpFlows)
}

func (a *Assembler) AssembleTCP(flowKey string, payload []byte) (*Hello, error) {
	flow, known := a.tcpFlows[flowKey]
	if !known {
		if payload[0] != contentTypeHandshake {
			return nil, nil
		}
		flow = &tcpFlow{}
		a.tcpFlows[flowKey] = flow
	}
	if flow.done {
		return nil, nil
	}
	flow.body = append(flow.body, payload...)
	if len(flow.body) > maxFlowBuffer {
		flow.done = true
		return nil, nil
	}
	hello, err := ParseHello(flow.body)
	if err != nil {
		return nil, nil
	}
	flow.done = true

	return hello, nil
}

func (a *Assembler) AssembleDTLS(flowKey string, payload []byte) (*Hello, error) {
	fragment, err := ParseDTLSFragment(payload)
	if err != nil {
		return nil, err
	}
	if !fragment.IsHello() || fragment.Length > maxFlowBuffer {
		return nil, nil
	}

	key := fmt.Sprintf("%s#%d#%d", flowKey, fragment.MessageSeq, fragment.Length)
	pending, known := a.dtlsFrags[key]
	if !known {
		pending = &dtlsAssembly{body: make([]byte, fragment.Length), filled: make([]bool, fragment.Length)}
		a.dtlsFrags[key] = pending
	}
	copy(pending.body[fragment.Offset:], fragment.Body)
	for i := fragment.Offset; i < fragment.Offset+fragment.FragmentLen; i++ {
		pending.filled[i] = true
	}
	for _, done := range pending.filled {
		if !done {
			return nil, nil
		}
	}

	delete(a.dtlsFrags, key)

	return ParseHello(fragment.Reassemble(pending.body))
}

// The client retransmits its Initial, so a reported connection is remembered
// rather than forgotten, or the same hello is assembled and reported again.
func (a *Assembler) AssembleQUIC(payload []byte) (*QUICInitial, *Hello) {
	initial, err := ParseQUICInitial(payload)
	if err != nil || len(initial.Crypto) == 0 {
		return nil, nil
	}

	key := hex.EncodeToString(initial.DestConnID)
	stream, known := a.quicStreams[key]
	if !known {
		stream = &quicStream{}
		a.quicStreams[key] = stream
	}
	if stream.done {
		return nil, nil
	}

	stream.chunks = append(stream.chunks, initial.Crypto...)
	handshake := AssembleCrypto(stream.chunks)
	if len(handshake) < 4 {
		return nil, nil
	}
	total := 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
	if len(handshake) < total {
		return nil, nil
	}

	record, err := CryptoRecord(handshake[:total])
	if err != nil {
		return nil, nil
	}
	hello, err := ParseHello(record)
	if err != nil {
		return nil, nil
	}
	stream.done = true
	initial.Crypto = stream.chunks
	stream.chunks = nil

	return initial, hello
}
