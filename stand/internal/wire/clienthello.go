package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	contentTypeHandshake = 22

	handshakeClientHello = 1
	handshakeServerHello = 2

	versionDTLS10 = 0xfeff
	versionDTLS12 = 0xfefd

	extServerName          = 0x0000
	extSupportedGroups     = 0x000a
	extQUICTransportParams = 0x0039
	extECPointFormats      = 0x000b
	extSignatureAlgorithms = 0x000d
	extALPN                = 0x0010
	extUseSRTP             = 0x000e
	extSupportedVersions   = 0x002b
	extKeyShare            = 0x0033

	tlsRecordHeaderLen       = 5
	dtlsRecordHeaderLen      = 13
	tlsHandshakeHeaderLen    = 4
	dtlsHandshakeHeaderLen   = 12
	helloRandomLen           = 32
	maxReasonableHelloLength = 1 << 16
)

var (
	ErrNotHandshake = errors.New("wire: not a handshake record")
	ErrNotHello     = errors.New("wire: not a client or server hello")
	ErrTruncated    = errors.New("wire: record truncated")
	ErrFragmented   = errors.New("wire: handshake message is fragmented")
)

type HelloKind string

const (
	HelloTLSClient  HelloKind = "tls-client-hello"
	HelloTLSServer  HelloKind = "tls-server-hello"
	HelloDTLSClient HelloKind = "dtls-client-hello"
	HelloDTLSServer HelloKind = "dtls-server-hello"
)

// Extension records where each extension sat inside the record, because a
// censor can match on the byte offset of a value that is itself unremarkable.
type Extension struct {
	Type   uint16 `json:"type"`
	Length uint16 `json:"length"`
	Offset int    `json:"offset"`
}

type Hello struct {
	Kind                HelloKind            `json:"kind"`
	RecordVersion       uint16               `json:"recordVersion"`
	HelloVersion        uint16               `json:"helloVersion"`
	MessageSeq          uint16               `json:"messageSeq"`
	SessionIDLen        int                  `json:"sessionIdLen"`
	CookieLen           int                  `json:"cookieLen"`
	CipherSuites        []uint16             `json:"cipherSuites"`
	CompressionMethods  []uint8              `json:"compressionMethods"`
	Extensions          []Extension          `json:"extensions"`
	ServerName          string               `json:"serverName,omitempty"`
	SupportedGroups     []uint16             `json:"supportedGroups,omitempty"`
	SupportedVersions   []uint16             `json:"supportedVersions,omitempty"`
	KeyShareGroups      []uint16             `json:"keyShareGroups,omitempty"`
	KeyShareLengths     []int                `json:"keyShareLengths,omitempty"`
	PointFormats        []uint8              `json:"pointFormats,omitempty"`
	SignatureAlgorithms []uint16             `json:"signatureAlgorithms,omitempty"`
	ALPN                []string             `json:"alpn,omitempty"`
	QUICTransportParams []QUICTransportParam `json:"quicTransportParams,omitempty"`
	UseSRTPProfiles     []uint16             `json:"useSrtpProfiles,omitempty"`
	Raw                 []byte               `json:"raw"`
}

func (h *Hello) IsDTLS() bool {
	return h.Kind == HelloDTLSClient || h.Kind == HelloDTLSServer
}

// ExtensionOffset returns the offset of an extension from the start of the
// record, or -1. Offsets are what published DPI signatures pin.
func (h *Hello) ExtensionOffset(extensionType uint16) int {
	for _, extension := range h.Extensions {
		if extension.Type == extensionType {
			return extension.Offset
		}
	}
	return -1
}

func (h *Hello) ExtensionTypes() []uint16 {
	types := make([]uint16, len(h.Extensions))
	for i, extension := range h.Extensions {
		types[i] = extension.Type
	}
	return types
}

type DTLSFragment struct {
	MessageType uint8
	MessageSeq  uint16
	Length      uint32
	Offset      uint32
	FragmentLen uint32
	Body        []byte
}

func (f *DTLSFragment) IsHello() bool {
	return f.MessageType == handshakeClientHello || f.MessageType == handshakeServerHello
}

// Reassemble rebuilds the record a complete message would have arrived in, so the
// result can go through ParseHello unchanged.
func (f *DTLSFragment) Reassemble(body []byte) []byte {
	record := make([]byte, 0, dtlsRecordHeaderLen+dtlsHandshakeHeaderLen+len(body))
	record = append(record, contentTypeHandshake, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0)
	record = binary.BigEndian.AppendUint16(record, uint16(dtlsHandshakeHeaderLen+len(body)))
	record = append(record, f.MessageType)
	record = appendUint24(record, uint32(len(body)))
	record = binary.BigEndian.AppendUint16(record, f.MessageSeq)
	record = appendUint24(record, 0)
	record = appendUint24(record, uint32(len(body)))
	return append(record, body...)
}

func ParseDTLSFragment(record []byte) (*DTLSFragment, error) {
	if len(record) < dtlsRecordHeaderLen+dtlsHandshakeHeaderLen {
		return nil, ErrTruncated
	}
	if record[0] != contentTypeHandshake {
		return nil, ErrNotHandshake
	}
	if version := binary.BigEndian.Uint16(record[1:3]); version != versionDTLS10 && version != versionDTLS12 {
		return nil, ErrNotHandshake
	}

	reader := &byteReader{buf: record, pos: dtlsRecordHeaderLen}
	fragment := &DTLSFragment{}
	messageType, err := reader.u8()
	if err != nil {
		return nil, err
	}
	fragment.MessageType = messageType
	if fragment.Length, err = reader.u24(); err != nil {
		return nil, err
	}
	if fragment.MessageSeq, err = reader.u16(); err != nil {
		return nil, err
	}
	if fragment.Offset, err = reader.u24(); err != nil {
		return nil, err
	}
	if fragment.FragmentLen, err = reader.u24(); err != nil {
		return nil, err
	}
	if fragment.Body, err = reader.bytes(int(fragment.FragmentLen)); err != nil {
		return nil, err
	}
	if fragment.Offset+fragment.FragmentLen > fragment.Length {
		return nil, ErrTruncated
	}
	return fragment, nil
}

func appendUint24(dst []byte, value uint32) []byte {
	return append(dst, byte(value>>16), byte(value>>8), byte(value))
}

// ParseHello reads one TLS or DTLS handshake record. record must start at the
// content type byte, so offsets in the result are relative to that.
func ParseHello(record []byte) (*Hello, error) {
	if len(record) < tlsRecordHeaderLen {
		return nil, ErrTruncated
	}
	if record[0] != contentTypeHandshake {
		return nil, ErrNotHandshake
	}
	version := binary.BigEndian.Uint16(record[1:3])
	isDTLS := version == versionDTLS10 || version == versionDTLS12

	headerLen := tlsRecordHeaderLen
	if isDTLS {
		headerLen = dtlsRecordHeaderLen
	}
	if len(record) < headerLen+1 {
		return nil, ErrTruncated
	}

	hello := &Hello{RecordVersion: version, Raw: record}
	reader := &byteReader{buf: record, pos: headerLen}

	messageType, err := reader.u8()
	if err != nil {
		return nil, err
	}
	if messageType != handshakeClientHello && messageType != handshakeServerHello {
		return nil, ErrNotHello
	}
	messageLen, err := reader.u24()
	if err != nil {
		return nil, err
	}
	if isDTLS {
		messageSeq, err := reader.u16()
		if err != nil {
			return nil, err
		}
		hello.MessageSeq = messageSeq
		fragmentOffset, err := reader.u24()
		if err != nil {
			return nil, err
		}
		fragmentLen, err := reader.u24()
		if err != nil {
			return nil, err
		}
		// Parsing a later fragment as if it began the message would yield a
		// plausible-looking hello built from the middle of one.
		if fragmentOffset != 0 || fragmentLen != messageLen {
			return nil, ErrFragmented
		}
	}

	switch {
	case isDTLS && messageType == handshakeClientHello:
		hello.Kind = HelloDTLSClient
	case isDTLS:
		hello.Kind = HelloDTLSServer
	case messageType == handshakeClientHello:
		hello.Kind = HelloTLSClient
	default:
		hello.Kind = HelloTLSServer
	}

	if err := parseHelloBody(reader, hello, isDTLS, messageType == handshakeClientHello); err != nil {
		return nil, err
	}
	return hello, nil
}

func parseHelloBody(reader *byteReader, hello *Hello, isDTLS, isClient bool) error {
	helloVersion, err := reader.u16()
	if err != nil {
		return err
	}
	hello.HelloVersion = helloVersion
	if _, err := reader.skip(helloRandomLen); err != nil {
		return err
	}

	sessionIDLen, err := reader.u8()
	if err != nil {
		return err
	}
	hello.SessionIDLen = int(sessionIDLen)
	if _, err := reader.skip(int(sessionIDLen)); err != nil {
		return err
	}

	if isDTLS && isClient {
		cookieLen, err := reader.u8()
		if err != nil {
			return err
		}
		hello.CookieLen = int(cookieLen)
		if _, err := reader.skip(int(cookieLen)); err != nil {
			return err
		}
	}

	if isClient {
		suitesLen, err := reader.u16()
		if err != nil {
			return err
		}
		suites, err := reader.bytes(int(suitesLen))
		if err != nil {
			return err
		}
		hello.CipherSuites = uint16List(suites)

		compressionLen, err := reader.u8()
		if err != nil {
			return err
		}
		compression, err := reader.bytes(int(compressionLen))
		if err != nil {
			return err
		}
		hello.CompressionMethods = append([]uint8(nil), compression...)
	} else {
		suite, err := reader.u16()
		if err != nil {
			return err
		}
		hello.CipherSuites = []uint16{suite}
		method, err := reader.u8()
		if err != nil {
			return err
		}
		hello.CompressionMethods = []uint8{method}
	}

	return parseExtensions(reader, hello)
}

func parseExtensions(reader *byteReader, hello *Hello) error {
	if reader.remaining() == 0 {
		return nil
	}
	totalLen, err := reader.u16()
	if err != nil {
		return err
	}
	end := reader.pos + int(totalLen)
	if end > len(reader.buf) {
		return ErrTruncated
	}
	for reader.pos < end {
		offset := reader.pos
		extensionType, err := reader.u16()
		if err != nil {
			return err
		}
		extensionLen, err := reader.u16()
		if err != nil {
			return err
		}
		body, err := reader.bytes(int(extensionLen))
		if err != nil {
			return err
		}
		hello.Extensions = append(hello.Extensions, Extension{
			Type:   extensionType,
			Length: extensionLen,
			Offset: offset,
		})
		applyKnownExtension(hello, extensionType, body)
	}
	return nil
}

func applyKnownExtension(hello *Hello, extensionType uint16, body []byte) {
	switch extensionType {
	case extSupportedGroups:
		if len(body) >= 2 {
			hello.SupportedGroups = uint16List(body[2:])
		}
	case extSignatureAlgorithms:
		if len(body) >= 2 {
			hello.SignatureAlgorithms = uint16List(body[2:])
		}
	case extECPointFormats:
		if len(body) >= 1 {
			hello.PointFormats = append([]uint8(nil), body[1:]...)
		}
	case extUseSRTP:
		if len(body) >= 2 {
			listLen := int(binary.BigEndian.Uint16(body[:2]))
			if listLen <= len(body)-2 {
				hello.UseSRTPProfiles = uint16List(body[2 : 2+listLen])
			}
		}
	case extALPN:
		hello.ALPN = parseALPN(body)
	case extQUICTransportParams:
		hello.QUICTransportParams = ParseQUICTransportParams(body)
	case extServerName:
		hello.ServerName = parseServerName(body)
	case extSupportedVersions:
		if len(body) >= 1 {
			hello.SupportedVersions = uint16List(body[1:])
		}
	case extKeyShare:
		hello.KeyShareGroups, hello.KeyShareLengths = parseKeyShare(body)
	}
}

func parseServerName(body []byte) string {
	pos := 2
	for pos+3 <= len(body) {
		nameType := body[pos]
		length := int(binary.BigEndian.Uint16(body[pos+1 : pos+3]))
		pos += 3
		if pos+length > len(body) {
			break
		}
		if nameType == 0 {
			return string(body[pos : pos+length])
		}
		pos += length
	}
	return ""
}

func parseKeyShare(body []byte) ([]uint16, []int) {
	var groups []uint16
	var lengths []int
	pos := 2
	for pos+4 <= len(body) {
		group := binary.BigEndian.Uint16(body[pos : pos+2])
		length := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+length > len(body) {
			break
		}
		groups = append(groups, group)
		lengths = append(lengths, length)
		pos += length
	}
	return groups, lengths
}

func parseALPN(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	var protocols []string
	pos := 2
	for pos < len(body) {
		length := int(body[pos])
		pos++
		if pos+length > len(body) {
			break
		}
		protocols = append(protocols, string(body[pos:pos+length]))
		pos += length
	}
	return protocols
}

func uint16List(buf []byte) []uint16 {
	values := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		values = append(values, binary.BigEndian.Uint16(buf[i:i+2]))
	}
	return values
}

type byteReader struct {
	buf []byte
	pos int
}

func (r *byteReader) remaining() int {
	return len(r.buf) - r.pos
}

func (r *byteReader) u8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, fmt.Errorf("u8 at %d: %w", r.pos, ErrTruncated)
	}
	value := r.buf[r.pos]
	r.pos++
	return value, nil
}

func (r *byteReader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("u16 at %d: %w", r.pos, ErrTruncated)
	}
	value := binary.BigEndian.Uint16(r.buf[r.pos : r.pos+2])
	r.pos += 2
	return value, nil
}

func (r *byteReader) u24() (uint32, error) {
	if r.remaining() < 3 {
		return 0, fmt.Errorf("u24 at %d: %w", r.pos, ErrTruncated)
	}
	value := uint32(r.buf[r.pos])<<16 | uint32(r.buf[r.pos+1])<<8 | uint32(r.buf[r.pos+2])
	r.pos += 3
	return value, nil
}

func (r *byteReader) bytes(n int) ([]byte, error) {
	if n < 0 || n > maxReasonableHelloLength || r.remaining() < n {
		return nil, fmt.Errorf("bytes(%d) at %d: %w", n, r.pos, ErrTruncated)
	}
	value := r.buf[r.pos : r.pos+n]
	r.pos += n
	return value, nil
}

func (r *byteReader) skip(n int) (int, error) {
	if _, err := r.bytes(n); err != nil {
		return 0, err
	}
	return r.pos, nil
}
