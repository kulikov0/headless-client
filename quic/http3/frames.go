package http3

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/kulikov0/headless-client/quic"
	"github.com/kulikov0/headless-client/quic/http3/qlog"
	"github.com/kulikov0/headless-client/quic/qlogwriter"
	"github.com/kulikov0/headless-client/quic/quicvarint"
)

// FrameType is the frame type of a HTTP/3 frame
type FrameType uint64

type frame any

// The maximum length of an encoded HTTP/3 frame header is 16:
// The frame has a type and length field, both QUIC varints (maximum 8 bytes in length)
const frameHeaderLen = 16

type countingByteReader struct {
	quicvarint.Reader
	NumRead int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.Reader.ReadByte()
	if err == nil {
		r.NumRead++
	}
	return b, err
}

func (r *countingByteReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.NumRead += n
	return n, err
}

func (r *countingByteReader) Reset() {
	r.NumRead = 0
}

type frameParser struct {
	r         io.Reader
	streamID  quic.StreamID
	closeConn func(quic.ApplicationErrorCode, string) error
}

func (p *frameParser) ParseNext(qlogger qlogwriter.Recorder) (frame, error) {
	r := &countingByteReader{Reader: quicvarint.NewReader(p.r)}
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		l, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}

		switch t {
		case 0x0: // DATA
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw: qlog.RawInfo{
						Length:        int(l) + r.NumRead,
						PayloadLength: int(l),
					},
					Frame: qlog.Frame{Frame: qlog.DataFrame{}},
				})
			}
			return &dataFrame{Length: l}, nil
		case 0x1: // HEADERS
			return &headersFrame{
				Length:    l,
				headerLen: r.NumRead,
			}, nil
		case 0x4: // SETTINGS
			return parseSettingsFrame(r, l, p.streamID, qlogger)
		case 0x3: // unsupported: CANCEL_PUSH
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.CancelPushFrame{}},
				})
			}
		case 0x5: // unsupported: PUSH_PROMISE
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.PushPromiseFrame{}},
				})
			}
		case 0x7: // GOAWAY
			return parseGoAwayFrame(r, l, p.streamID, qlogger)
		case 0xd: // unsupported: MAX_PUSH_ID
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.MaxPushIDFrame{}},
				})
			}
		case 0x2, 0x6, 0x8, 0x9: // reserved frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.ReservedFrame{Type: t}},
				})
			}
			p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, fmt.Errorf("http3: reserved frame type: %d", t)
		default:
			// unknown frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.UnknownFrame{Type: t}},
				})
			}
		}

		// skip over the payload
		if _, err := io.CopyN(io.Discard, r, int64(l)); err != nil {
			return nil, err
		}
		r.Reset()
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x0)
	return quicvarint.Append(b, f.Length)
}

type headersFrame struct {
	Length    uint64
	headerLen int // number of bytes read for type and length field
}

func (f *headersFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x1)
	return quicvarint.Append(b, f.Length)
}

const (
	// QPACK settings
	settingQPACKMaxTableCapacity = 0x1
	settingQPACKBlockedStreams   = 0x7
	// SETTINGS_MAX_FIELD_SECTION_SIZE
	settingMaxFieldSectionSize = 0x6
	// Extended CONNECT, RFC 9220
	settingExtendedConnect = 0x8
	// HTTP Datagrams, RFC 9297
	settingDatagram = 0x33
)

type settingsFrame struct {
	// QPACK settings (Chrome order: 1, 6, 7, 51, GREASE)
	QPACKMaxTableCapacity int64 // SETTINGS_QPACK_MAX_TABLE_CAPACITY, -1 if not set
	MaxFieldSectionSize   int64 // SETTINGS_MAX_FIELD_SECTION_SIZE, -1 if not set
	QPACKBlockedStreams   int64 // SETTINGS_QPACK_BLOCKED_STREAMS, -1 if not set

	Datagram        bool              // HTTP Datagrams, RFC 9297
	ExtendedConnect bool              // Extended CONNECT, RFC 9220
	Other           map[uint64]uint64 // all settings that we don't explicitly recognize
}

func pointer[T any](v T) *T {
	return &v
}

func parseSettingsFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*settingsFrame, error) {
	if l > 8*(1<<10) {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	frame := &settingsFrame{
		QPACKMaxTableCapacity: -1,
		MaxFieldSectionSize:   -1,
		QPACKBlockedStreams:   -1,
	}
	b := bytes.NewReader(buf)
	settingsFrame := qlog.SettingsFrame{MaxFieldSectionSize: -1}
	var readMaxFieldSectionSize, readDatagram, readExtendedConnect bool
	var readQPACKMaxTableCapacity, readQPACKBlockedStreams bool
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		val, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}

		switch id {
		case settingQPACKMaxTableCapacity:
			if readQPACKMaxTableCapacity {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readQPACKMaxTableCapacity = true
			frame.QPACKMaxTableCapacity = int64(val)
		case settingQPACKBlockedStreams:
			if readQPACKBlockedStreams {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readQPACKBlockedStreams = true
			frame.QPACKBlockedStreams = int64(val)
		case settingMaxFieldSectionSize:
			if readMaxFieldSectionSize {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readMaxFieldSectionSize = true
			frame.MaxFieldSectionSize = int64(val)
			settingsFrame.MaxFieldSectionSize = int64(val)
		case settingExtendedConnect:
			if readExtendedConnect {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readExtendedConnect = true
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: %d", val)
			}
			frame.ExtendedConnect = val == 1
			if qlogger != nil {
				settingsFrame.ExtendedConnect = pointer(frame.ExtendedConnect)
			}
		case settingDatagram:
			if readDatagram {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readDatagram = true
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for SETTINGS_H3_DATAGRAM: %d", val)
			}
			frame.Datagram = val == 1
			if qlogger != nil {
				settingsFrame.Datagram = pointer(frame.Datagram)
			}
		default:
			if _, ok := frame.Other[id]; ok {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if frame.Other == nil {
				frame.Other = make(map[uint64]uint64)
			}
			frame.Other[id] = val
		}
	}
	if qlogger != nil {
		settingsFrame.Other = maps.Clone(frame.Other)

		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw: qlog.RawInfo{
				Length:        r.NumRead,
				PayloadLength: int(l),
			},
			Frame: qlog.Frame{Frame: settingsFrame},
		})
	}
	return frame, nil
}

func (f *settingsFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x4)
	entries := make([][2]uint64, 0, len(f.Other)+5)
	if f.QPACKMaxTableCapacity >= 0 {
		entries = append(entries, [2]uint64{settingQPACKMaxTableCapacity, uint64(f.QPACKMaxTableCapacity)})
	}
	if f.MaxFieldSectionSize >= 0 {
		entries = append(entries, [2]uint64{settingMaxFieldSectionSize, uint64(f.MaxFieldSectionSize)})
	}
	if f.QPACKBlockedStreams >= 0 {
		entries = append(entries, [2]uint64{settingQPACKBlockedStreams, uint64(f.QPACKBlockedStreams)})
	}
	if f.Datagram {
		entries = append(entries, [2]uint64{settingDatagram, 1})
	}
	if f.ExtendedConnect {
		entries = append(entries, [2]uint64{settingExtendedConnect, 1})
	}
	for id, val := range f.Other {
		entries = append(entries, [2]uint64{id, val})
	}
	slices.SortFunc(entries, func(a, b [2]uint64) int { return cmp.Compare(a[0], b[0]) })

	var l int
	for _, entry := range entries {
		l += quicvarint.Len(entry[0]) + quicvarint.Len(entry[1])
	}
	b = quicvarint.Append(b, uint64(l))
	for _, entry := range entries {
		b = quicvarint.Append(b, entry[0])
		b = quicvarint.Append(b, entry[1])
	}

	return b
}

type goAwayFrame struct {
	StreamID quic.StreamID
}

func parseGoAwayFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*goAwayFrame, error) {
	frame := &goAwayFrame{}
	startLen := r.NumRead
	id, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if r.NumRead-startLen != int(l) {
		return nil, errors.New("GOAWAY frame: inconsistent length")
	}
	frame.StreamID = quic.StreamID(id)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
			Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: frame.StreamID}},
		})
	}
	return frame, nil
}

func (f *goAwayFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x7)
	b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(f.StreamID))))
	return quicvarint.Append(b, uint64(f.StreamID))
}
