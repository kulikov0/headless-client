package wire

import "sort"

const maxStreamBytes = 1 << 20

type tcpStream struct {
	base     uint32
	hasBase  bool
	stored   int
	segments map[uint32][]byte
}

type Streams struct {
	streams map[string]*tcpStream
	order   []string
}

func NewStreams() *Streams {
	return &Streams{streams: map[string]*tcpStream{}}
}

func (a *Streams) stream(flowKey string) *tcpStream {
	stream, known := a.streams[flowKey]
	if !known {
		stream = &tcpStream{segments: map[uint32][]byte{}}
		a.streams[flowKey] = stream
		a.order = append(a.order, flowKey)
	}
	return stream
}

func (a *Streams) SYN(flowKey string, sequence uint32) {
	stream := a.stream(flowKey)
	if !stream.hasBase {
		stream.base = sequence + 1
		stream.hasBase = true
	}
}

func (a *Streams) Add(flowKey string, sequence uint32, payload []byte) {
	stream := a.stream(flowKey)
	if !stream.hasBase {
		stream.base = sequence
		stream.hasBase = true
	}
	offset := sequence - stream.base
	if offset >= maxStreamBytes || stream.stored >= maxStreamBytes {
		return
	}
	if existing := stream.segments[offset]; len(existing) >= len(payload) {
		return
	}
	stream.segments[offset] = append([]byte(nil), payload...)
	stream.stored += len(payload)
}

func (a *Streams) Keys() []string {
	return a.order
}

func (a *Streams) Stream(flowKey string) []byte {
	stream, known := a.streams[flowKey]
	if !known {
		return nil
	}
	offsets := make([]uint32, 0, len(stream.segments))
	for offset := range stream.segments {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	var body []byte
	var position uint32
	for _, offset := range offsets {
		segment := stream.segments[offset]
		end := offset + uint32(len(segment))
		if offset > position {
			break
		}
		if end <= position {
			continue
		}
		body = append(body, segment[position-offset:]...)
		position = end
	}
	return body
}
