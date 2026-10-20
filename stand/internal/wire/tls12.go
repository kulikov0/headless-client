package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	contentTypeChangeCipherSpec = 20

	gcmExplicitNonceLen = 8
)

type tls12Suite struct {
	newHash func() hash.Hash
	keyLen  int
	ivLen   int
	chacha  bool
}

var tls12Suites = map[uint16]tls12Suite{
	0x009c: {sha256.New, 16, 4, false},    // TLS_RSA_WITH_AES_128_GCM_SHA256
	0x009d: {sha512.New384, 32, 4, false}, // TLS_RSA_WITH_AES_256_GCM_SHA384
	0xc02b: {sha256.New, 16, 4, false},    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc02c: {sha512.New384, 32, 4, false}, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc02f: {sha256.New, 16, 4, false},    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xc030: {sha512.New384, 32, 4, false}, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xcca8: {sha256.New, 32, 12, true},    // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	0xcca9: {sha256.New, 32, 12, true},    // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
}

func Decrypt12(stream []byte, cipherSuite uint16, masterSecret, clientRandom, serverRandom []byte) ([]byte, error) {
	suite, known := tls12Suites[cipherSuite]
	if !known {
		return nil, fmt.Errorf("wire: tls 1.2 cipher suite 0x%04x is not supported", cipherSuite)
	}
	keyBlock := tls12PRF(suite.newHash, masterSecret, "key expansion",
		append(append([]byte(nil), serverRandom...), clientRandom...), 2*suite.keyLen+2*suite.ivLen)
	key := keyBlock[:suite.keyLen]
	iv := keyBlock[2*suite.keyLen : 2*suite.keyLen+suite.ivLen]

	var aead cipher.AEAD
	var err error
	if suite.chacha {
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

	encrypted := false
	var sequence uint64
	var data []byte
	for len(data) < maxStreamBytes {
		header, body, rest, ok := nextRecord(stream)
		if !ok {
			break
		}
		stream = rest
		if !encrypted {
			encrypted = header[0] == contentTypeChangeCipherSpec
			continue
		}

		var nonce []byte
		if suite.chacha {
			nonce = xorNonce(iv, sequence)
		} else {
			if len(body) < gcmExplicitNonceLen {
				return data, ErrTLSDecrypt
			}
			nonce = append(append([]byte(nil), iv...), body[:gcmExplicitNonceLen]...)
			body = body[gcmExplicitNonceLen:]
		}
		if len(body) < aead.Overhead() {
			return data, ErrTLSDecrypt
		}
		additional := binary.BigEndian.AppendUint64(nil, sequence)
		additional = append(additional, header[:3]...)
		additional = binary.BigEndian.AppendUint16(additional, uint16(len(body)-aead.Overhead()))
		plaintext, err := aead.Open(nil, nonce, body, additional)
		if err != nil {
			return data, ErrTLSDecrypt
		}
		sequence++

		switch header[0] {
		case contentTypeApplicationData:
			data = append(data, plaintext...)
		case contentTypeAlert:
			return data, nil
		}
	}
	return data, nil
}

// RFC 5246 section 5
func tls12PRF(newHash func() hash.Hash, secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	mac := hmac.New(newHash, secret)
	mac.Write(labelAndSeed)
	a := mac.Sum(nil)

	var out []byte
	for len(out) < length {
		mac.Reset()
		mac.Write(a)
		mac.Write(labelAndSeed)
		out = mac.Sum(out)

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:length]
}
