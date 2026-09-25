package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	contentTypeAlert           = 21
	contentTypeApplicationData = 23

	handshakeFinished = 20

	tlsAES128GCMSHA256        = 0x1301
	tlsAES256GCMSHA384        = 0x1302
	tlsChaCha20Poly1305SHA256 = 0x1303
)

var ErrTLSDecrypt = errors.New("wire: tls record decryption failed")

type recordProtection struct {
	aead     cipher.AEAD
	iv       []byte
	sequence uint64
}

func newRecordProtection(suite uint16, secret []byte) (*recordProtection, error) {
	var newHash func() hash.Hash = sha256.New
	keyLen := 16
	switch suite {
	case tlsAES128GCMSHA256:
	case tlsAES256GCMSHA384:
		newHash, keyLen = sha512.New384, 32
	case tlsChaCha20Poly1305SHA256:
		keyLen = 32
	default:
		return nil, fmt.Errorf("wire: cipher suite 0x%04x is not a tls 1.3 suite", suite)
	}

	key, err := expandLabelHash(newHash, secret, "key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabelHash(newHash, secret, "iv", 12)
	if err != nil {
		return nil, err
	}

	var aead cipher.AEAD
	if suite == tlsChaCha20Poly1305SHA256 {
		aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		return nil, err
	}
	return &recordProtection{aead: aead, iv: iv}, nil
}

func (p *recordProtection) open(header, body []byte) (byte, []byte, error) {
	plaintext, err := p.aead.Open(nil, xorNonce(p.iv, p.sequence), body, header)
	if err != nil {
		return 0, nil, ErrTLSDecrypt
	}
	p.sequence++
	end := len(plaintext)
	for end > 0 && plaintext[end-1] == 0 {
		end--
	}
	if end == 0 {
		return 0, nil, ErrTLSDecrypt
	}
	return plaintext[end-1], plaintext[:end-1], nil
}

func Decrypt13(stream []byte, suite uint16, handshakeSecret, trafficSecret []byte) ([]byte, error) {
	handshake, err := newRecordProtection(suite, handshakeSecret)
	if err != nil {
		return nil, err
	}
	traffic, err := newRecordProtection(suite, trafficSecret)
	if err != nil {
		return nil, err
	}

	current := handshake
	var data []byte
	for len(data) < maxStreamBytes {
		header, body, rest, ok := nextRecord(stream)
		if !ok {
			break
		}
		stream = rest
		if header[0] != contentTypeApplicationData {
			continue
		}

		contentType, plaintext, err := current.open(header, body)
		if err != nil {
			return data, err
		}
		switch contentType {
		case contentTypeHandshake:
			if current == handshake && endsWithFinished(plaintext) {
				current = traffic
			}
		case contentTypeApplicationData:
			data = append(data, plaintext...)
		case contentTypeAlert:
			return data, nil
		}
	}
	return data, nil
}

func nextRecord(stream []byte) (header, body, rest []byte, ok bool) {
	if len(stream) < tlsRecordHeaderLen {
		return nil, nil, nil, false
	}
	end := tlsRecordHeaderLen + int(binary.BigEndian.Uint16(stream[3:5]))
	if len(stream) < end {
		return nil, nil, nil, false
	}
	return stream[:tlsRecordHeaderLen], stream[tlsRecordHeaderLen:end], stream[end:], true
}

func endsWithFinished(messages []byte) bool {
	last := byte(0)
	for len(messages) >= tlsHandshakeHeaderLen {
		length := int(messages[1])<<16 | int(messages[2])<<8 | int(messages[3])
		if len(messages) < tlsHandshakeHeaderLen+length {
			return false
		}
		last = messages[0]
		messages = messages[tlsHandshakeHeaderLen+length:]
	}
	return last == handshakeFinished
}
