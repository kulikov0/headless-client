package wire

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

func (h *Hello) JA3() string {
	fields := []string{
		strconv.Itoa(int(h.HelloVersion)),
		joinUint16(WithoutGREASE(h.CipherSuites)),
		joinUint16(WithoutGREASE(h.ExtensionTypes())),
		joinUint16(WithoutGREASE(h.SupportedGroups)),
		joinUint8(h.PointFormats),
	}
	return strings.Join(fields, ",")
}

func (h *Hello) JA3Hash() string {
	sum := md5.Sum([]byte(h.JA3()))
	return hex.EncodeToString(sum[:])
}

func IsGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&0xff
}

func WithoutGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, value := range values {
		if !IsGREASE(value) {
			out = append(out, value)
		}
	}
	return out
}

func joinUint16(values []uint16) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, "-")
}

func joinUint8(values []uint8) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, "-")
}
