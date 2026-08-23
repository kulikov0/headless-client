package wire

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	stunHeaderLen   = 20
	stunMagicCookie = 0x2112a442

	stunAttrUsername = 0x0006
	stunAttrSoftware = 0x8022
)

var ErrNotSTUN = errors.New("wire: not a stun message")

type STUNMessage struct {
	Type       uint16   `json:"type"`
	Username   string   `json:"username,omitempty"`
	Software   string   `json:"software,omitempty"`
	Attributes []uint16 `json:"attributes"`
}

// Ufrags splits the USERNAME attribute, which ICE forms as remote:local. Their
// lengths and alphabet differ per implementation and travel in the clear.
func (m *STUNMessage) Ufrags() (remote, local string) {
	parts := strings.SplitN(m.Username, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func ParseSTUN(payload []byte) (*STUNMessage, error) {
	if len(payload) < stunHeaderLen {
		return nil, ErrNotSTUN
	}
	if payload[0]&0xc0 != 0 {
		return nil, ErrNotSTUN
	}
	if binary.BigEndian.Uint32(payload[4:8]) != stunMagicCookie {
		return nil, ErrNotSTUN
	}
	bodyLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if stunHeaderLen+bodyLen > len(payload) {
		return nil, ErrNotSTUN
	}

	message := &STUNMessage{Type: binary.BigEndian.Uint16(payload[:2])}
	pos := stunHeaderLen
	end := stunHeaderLen + bodyLen
	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(payload[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > end {
			break
		}
		value := payload[pos : pos+attrLen]
		message.Attributes = append(message.Attributes, attrType)
		switch attrType {
		case stunAttrUsername:
			message.Username = string(value)
		case stunAttrSoftware:
			message.Software = string(value)
		}
		pos += attrLen
		if pad := attrLen % 4; pad != 0 {
			pos += 4 - pad
		}
	}
	return message, nil
}
