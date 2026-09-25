package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	ProtocolHTTP2  = "h2"
	ProtocolHTTP11 = "http/1.1"

	maxHPACKTableSize = 1 << 16
	maxHTTP2FrameSize = 1<<24 - 1
)

var errNotHTTP = errors.New("wire: application data is neither http/2 nor http/1.1")

type HTTP2Setting struct {
	ID    uint16
	Value uint32
}

type HTTP2Priority struct {
	StreamID  uint32
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

type HeaderField struct {
	Name  string
	Value string
}

type Request struct {
	RequestLine string
	Priority    *HTTP2Priority
	Headers     []HeaderField
}

type Session struct {
	Protocol     string
	Settings     []HTTP2Setting
	WindowUpdate uint32
	Priorities   []HTTP2Priority
	Requests     []Request
}

func ParseSession(data []byte) (*Session, error) {
	if preface := []byte(http2.ClientPreface); bytes.HasPrefix(data, preface) {
		return parseHTTP2(data[len(preface):])
	}
	return parseHTTP1(data)
}

func parseHTTP2(data []byte) (*Session, error) {
	framer := http2.NewFramer(io.Discard, bytes.NewReader(data))
	framer.ReadMetaHeaders = hpack.NewDecoder(maxHPACKTableSize, nil)
	framer.SetMaxReadFrameSize(maxHTTP2FrameSize)

	session := &Session{Protocol: ProtocolHTTP2}
	settingsSeen := false
	for {
		frame, err := framer.ReadFrame()
		var streamError http2.StreamError
		if errors.As(err, &streamError) {
			continue
		}
		if err != nil {
			break
		}

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() || settingsSeen {
				continue
			}
			settingsSeen = true
			frame.ForeachSetting(func(setting http2.Setting) error {
				session.Settings = append(session.Settings, HTTP2Setting{ID: uint16(setting.ID), Value: setting.Val})
				return nil
			})
		case *http2.WindowUpdateFrame:
			if frame.StreamID == 0 && session.WindowUpdate == 0 {
				session.WindowUpdate = frame.Increment
			}
		case *http2.PriorityFrame:
			session.Priorities = append(session.Priorities, http2Priority(frame.StreamID, frame.PriorityParam))
		case *http2.MetaHeadersFrame:
			var request Request
			if frame.HasPriority() {
				priority := http2Priority(frame.StreamID, frame.Priority)
				request.Priority = &priority
			}
			for _, field := range frame.Fields {
				request.Headers = append(request.Headers, HeaderField{Name: field.Name, Value: field.Value})
			}
			session.Requests = append(session.Requests, request)
		}
	}
	return session, nil
}

func http2Priority(streamID uint32, param http2.PriorityParam) HTTP2Priority {
	return HTTP2Priority{
		StreamID:  streamID,
		StreamDep: param.StreamDep,
		Exclusive: param.Exclusive,
		Weight:    param.Weight,
	}
}

func parseHTTP1(data []byte) (*Session, error) {
	head, _, found := bytes.Cut(data, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	if parts := strings.Split(lines[0], " "); !found || len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return nil, errNotHTTP
	}

	request := Request{RequestLine: lines[0]}
	for _, line := range lines[1:] {
		if name, value, found := strings.Cut(line, ":"); found {
			request.Headers = append(request.Headers, HeaderField{Name: name, Value: strings.TrimSpace(value)})
		}
	}
	return &Session{Protocol: ProtocolHTTP11, Requests: []Request{request}}, nil
}

// SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order
func (s *Session) Akamai() string {
	if s.Protocol != ProtocolHTTP2 {
		return "-"
	}
	settings := make([]string, len(s.Settings))
	for i, setting := range s.Settings {
		settings[i] = fmt.Sprintf("%d:%d", setting.ID, setting.Value)
	}
	priorities := []string{"0"}
	if len(s.Priorities) > 0 {
		priorities = priorities[:0]
		for _, priority := range s.Priorities {
			exclusive := 0
			if priority.Exclusive {
				exclusive = 1
			}
			priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d",
				priority.StreamID, exclusive, priority.StreamDep, int(priority.Weight)+1))
		}
	}
	var pseudo []string
	if len(s.Requests) > 0 {
		for _, field := range s.Requests[0].Headers {
			if strings.HasPrefix(field.Name, ":") && len(field.Name) > 1 {
				pseudo = append(pseudo, field.Name[1:2])
			}
		}
	}
	return strings.Join([]string{
		strings.Join(settings, ";"),
		strconv.FormatUint(uint64(s.WindowUpdate), 10),
		strings.Join(priorities, ","),
		strings.Join(pseudo, ","),
	}, "|")
}
