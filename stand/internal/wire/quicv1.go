package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	quicVersion1     = 0x00000001
	quicSampleLen    = 16
	quicMaxCryptoLen = 1 << 16

	quicFrameCrypto  = 0x06
	quicFramePadding = 0x00
	quicFramePing    = 0x01
	quicFrameAckLow  = 0x02
	quicFrameAckHigh = 0x03
)

// RFC 9001 section 5.2, the version 1 initial salt.
var quicInitialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

var (
	ErrNotQUICInitial  = errors.New("wire: not a quic initial packet")
	ErrQUICVersion     = errors.New("wire: unsupported quic version")
	ErrQUICUnprotected = errors.New("wire: quic header protection removal failed")
)

type QUICCryptoChunk struct {
	Offset uint64
	Data   []byte
}

type QUICInitial struct {
	Version    uint32
	DestConnID []byte
	SrcConnID  []byte
	PacketNum  uint64
	Crypto     []QUICCryptoChunk
	Rest       []byte
}

// ParseQUICInitial decrypts one Initial packet. Initial packets are protected with
// keys derived from the destination connection id, which travels in the clear, so
// this needs no secrets and works on any capture.
func ParseQUICInitial(datagram []byte) (*QUICInitial, error) {
	if len(datagram) < 7 || datagram[0]&0x80 == 0 {
		return nil, ErrNotQUICInitial
	}
	if (datagram[0]&0x30)>>4 != 0 {
		return nil, ErrNotQUICInitial
	}
	version := binary.BigEndian.Uint32(datagram[1:5])
	if version != quicVersion1 {
		return nil, fmt.Errorf("%w: %#08x", ErrQUICVersion, version)
	}

	reader := &byteReader{buf: datagram, pos: 5}
	destConnID, err := readQUICConnID(reader)
	if err != nil {
		return nil, err
	}
	srcConnID, err := readQUICConnID(reader)
	if err != nil {
		return nil, err
	}
	tokenLen, err := readQUICVarint(reader)
	if err != nil {
		return nil, err
	}
	if _, err := reader.bytes(int(tokenLen)); err != nil {
		return nil, err
	}
	remainder, err := readQUICVarint(reader)
	if err != nil {
		return nil, err
	}
	pnOffset := reader.pos
	if pnOffset+int(remainder) > len(datagram) || remainder < quicSampleLen+4 {
		return nil, ErrNotQUICInitial
	}

	key, iv, headerKey, err := quicClientInitialKeys(destConnID)
	if err != nil {
		return nil, err
	}

	packet := append([]byte(nil), datagram[:pnOffset+int(remainder)]...)
	sample := packet[pnOffset+4 : pnOffset+4+quicSampleLen]
	mask, err := quicHeaderMask(headerKey, sample)
	if err != nil {
		return nil, err
	}
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&0x03) + 1
	var packetNum uint64
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
		packetNum = packetNum<<8 | uint64(packet[pnOffset+i])
	}

	header := packet[:pnOffset+pnLen]
	ciphertext := packet[pnOffset+pnLen:]
	plaintext, err := quicDecrypt(key, iv, packetNum, header, ciphertext)
	if err != nil {
		return nil, err
	}

	initial := &QUICInitial{
		Version:    version,
		DestConnID: destConnID,
		SrcConnID:  srcConnID,
		PacketNum:  packetNum,
		Rest:       datagram[pnOffset+int(remainder):],
	}
	if initial.Crypto, err = quicCryptoFrames(plaintext); err != nil {
		return nil, err
	}
	return initial, nil
}

type QUICTransportParam struct {
	ID    uint64 `json:"id"`
	Value string `json:"value"`
}

// IsGREASE reports whether the parameter is one of the reserved values a client
// sends purely to keep middleboxes from ossifying, 31*N+27 per RFC 9000 18.1.
func (p QUICTransportParam) IsGREASE() bool {
	return p.ID >= 27 && (p.ID-27)%31 == 0
}

func ParseQUICTransportParams(body []byte) []QUICTransportParam {
	var params []QUICTransportParam
	reader := &byteReader{buf: body}
	for reader.remaining() > 0 {
		id, err := readQUICVarint(reader)
		if err != nil {
			return params
		}
		length, err := readQUICVarint(reader)
		if err != nil {
			return params
		}
		value, err := reader.bytes(int(length))
		if err != nil {
			return params
		}
		params = append(params, QUICTransportParam{ID: id, Value: hex.EncodeToString(value)})
	}
	return params
}

// CryptoRecord wraps a reassembled CRYPTO stream in a TLS record, since QUIC carries
// the handshake message without one and ParseHello expects a record.
func CryptoRecord(handshake []byte) ([]byte, error) {
	if len(handshake) > 1<<16-1 {
		return nil, ErrTruncated
	}
	record := []byte{contentTypeHandshake, 0x03, 0x01}
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...), nil
}

func quicClientInitialKeys(destConnID []byte) (key, iv, headerKey []byte, err error) {
	initialSecret, err := hkdf.Extract(sha256.New, destConnID, quicInitialSaltV1)
	if err != nil {
		return nil, nil, nil, err
	}
	clientSecret, err := expandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(clientSecret, "quic key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(clientSecret, "quic iv", 12); err != nil {
		return nil, nil, nil, err
	}
	if headerKey, err = expandLabel(clientSecret, "quic hp", 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, headerKey, nil
}

// expandLabel is HKDF-Expand-Label from TLS 1.3, which QUIC reuses verbatim.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func quicHeaderMask(headerKey, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(headerKey)
	if err != nil {
		return nil, err
	}
	if len(sample) < block.BlockSize() {
		return nil, ErrQUICUnprotected
	}
	mask := make([]byte, block.BlockSize())
	block.Encrypt(mask, sample)
	return mask, nil
}

func quicDecrypt(key, iv []byte, packetNum uint64, header, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), iv...)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], packetNum)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= counter[i]
	}
	return aead.Open(nil, nonce, ciphertext, header)
}

// quicCryptoFrames collects every CRYPTO frame in the packet. Chrome deliberately
// splits its ClientHello across several of them at scattered offsets, so taking only
// the first yields a few bytes.
func quicCryptoFrames(plaintext []byte) ([]QUICCryptoChunk, error) {
	var chunks []QUICCryptoChunk
	reader := &byteReader{buf: plaintext}
	for reader.remaining() > 0 {
		frameType, err := reader.u8()
		if err != nil {
			return chunks, nil
		}
		switch frameType {
		case quicFramePadding, quicFramePing:
			continue
		case quicFrameAckLow, quicFrameAckHigh:
			if err := skipQUICAck(reader, frameType); err != nil {
				return chunks, nil
			}
		case quicFrameCrypto:
			offset, err := readQUICVarint(reader)
			if err != nil {
				return chunks, nil
			}
			length, err := readQUICVarint(reader)
			if err != nil || length > quicMaxCryptoLen {
				return chunks, nil
			}
			data, err := reader.bytes(int(length))
			if err != nil {
				return chunks, nil
			}
			chunks = append(chunks, QUICCryptoChunk{Offset: offset, Data: append([]byte(nil), data...)})
		default:
			return chunks, nil
		}
	}
	return chunks, nil
}

// AssembleCrypto lays the chunks out by offset and returns the contiguous run from
// zero, which is as much of the handshake as this packet carries.
func AssembleCrypto(chunks []QUICCryptoChunk) []byte {
	var end uint64
	for _, chunk := range chunks {
		if finish := chunk.Offset + uint64(len(chunk.Data)); finish > end {
			end = finish
		}
	}
	if end == 0 || end > quicMaxCryptoLen {
		return nil
	}
	stream := make([]byte, end)
	filled := make([]bool, end)
	for _, chunk := range chunks {
		copy(stream[chunk.Offset:], chunk.Data)
		for i := chunk.Offset; i < chunk.Offset+uint64(len(chunk.Data)); i++ {
			filled[i] = true
		}
	}
	for i, done := range filled {
		if !done {
			return stream[:i]
		}
	}
	return stream
}

func skipQUICAck(reader *byteReader, frameType uint8) error {
	// largest_acknowledged then ack_delay, then the range count, then first_ack_range.
	for i := 0; i < 2; i++ {
		if _, err := readQUICVarint(reader); err != nil {
			return err
		}
	}
	rangeCount, err := readQUICVarint(reader)
	if err != nil {
		return err
	}
	if _, err := readQUICVarint(reader); err != nil {
		return err
	}
	for i := uint64(0); i < rangeCount; i++ {
		if _, err := readQUICVarint(reader); err != nil {
			return err
		}
		if _, err := readQUICVarint(reader); err != nil {
			return err
		}
	}
	if frameType == quicFrameAckHigh {
		for i := 0; i < 3; i++ {
			if _, err := readQUICVarint(reader); err != nil {
				return err
			}
		}
	}
	return nil
}

func readQUICConnID(reader *byteReader) ([]byte, error) {
	length, err := reader.u8()
	if err != nil {
		return nil, err
	}
	if length > 20 {
		return nil, ErrNotQUICInitial
	}
	return reader.bytes(int(length))
}

func readQUICVarint(reader *byteReader) (uint64, error) {
	first, err := reader.u8()
	if err != nil {
		return 0, err
	}
	extra := int(1<<(first>>6)) - 1
	value := uint64(first & 0x3f)
	for i := 0; i < extra; i++ {
		next, err := reader.u8()
		if err != nil {
			return 0, err
		}
		value = value<<8 | uint64(next)
	}
	return value, nil
}
