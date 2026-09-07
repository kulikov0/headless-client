package http3

import (
	"testing"

	"github.com/kulikov0/headless-client/quic/quicvarint"
)

func parseSettingsAndTrailingFrames(t *testing.T, b []byte) (settings [][2]uint64, trailingFrames [][2]uint64) {
	t.Helper()
	streamType, n, err := quicvarint.Parse(b)
	if err != nil {
		t.Fatalf("cannot parse the stream type: %v", err)
	}
	if streamType != streamTypeControlStream {
		t.Fatalf("stream type is 0x%x, want the control stream 0x%x", streamType, streamTypeControlStream)
	}
	b = b[n:]

	for len(b) > 0 {
		frameType, typeLen, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("cannot parse a frame type: %v", err)
		}
		b = b[typeLen:]
		payloadLen, lengthLen, err := quicvarint.Parse(b)
		if err != nil {
			t.Fatalf("cannot parse a frame length: %v", err)
		}
		b = b[lengthLen:]
		if uint64(len(b)) < payloadLen {
			t.Fatalf("frame 0x%x claims %d payload bytes, %d left", frameType, payloadLen, len(b))
		}
		payload := b[:payloadLen]
		b = b[payloadLen:]
		if frameType != 0x4 {
			trailingFrames = append(trailingFrames, [2]uint64{frameType, payloadLen})
			continue
		}
		for len(payload) > 0 {
			id, idLen, err := quicvarint.Parse(payload)
			if err != nil {
				t.Fatalf("cannot parse a setting identifier: %v", err)
			}
			payload = payload[idLen:]
			value, valueLen, err := quicvarint.Parse(payload)
			if err != nil {
				t.Fatalf("cannot parse a setting value: %v", err)
			}
			payload = payload[valueLen:]
			settings = append(settings, [2]uint64{id, value})
		}
	}

	return settings, trailingFrames
}

func newTestSettingsFrame() *settingsFrame {
	return &settingsFrame{
		QPACKMaxTableCapacity: -1,
		MaxFieldSectionSize:   -1,
		QPACKBlockedStreams:   -1,
		Other:                 map[uint64]uint64{0x2b603742: 1},
	}
}

func TestControlStreamSortsTheSettingsByIdentifier(t *testing.T) {
	// 0x02 sorts before MAX_FIELD_SECTION_SIZE, so a serializer that writes the
	// known identifiers first and then ranges over Other cannot pass this.
	frame := &settingsFrame{
		QPACKMaxTableCapacity: 65536,
		MaxFieldSectionSize:   16384,
		QPACKBlockedStreams:   100,
		Datagram:              true,
		Other:                 map[uint64]uint64{0xffd277: 1, 0x2b603742: 1, 0x02: 7},
	}
	settings, _ := parseSettingsAndTrailingFrames(t, appendControlStream(nil, frame, false))

	want := [][2]uint64{
		{0x01, 65536},
		{0x02, 7},
		{0x06, 16384},
		{0x07, 100},
		{0x33, 1},
		{0xffd277, 1},
		{0x2b603742, 1},
	}
	if len(settings) != len(want) {
		t.Fatalf("serialized %d settings, want %d: %v", len(settings), len(want), settings)
	}
	for i, entry := range want {
		if settings[i] != entry {
			t.Fatalf("setting %d is {0x%x, %d}, want {0x%x, %d}; the frame is not in ascending identifier order: %v",
				i, settings[i][0], settings[i][1], entry[0], entry[1], settings)
		}
	}
}

func TestControlStreamGreasesTheSettingsAndAppendsAGreasingFrame(t *testing.T) {
	const runs = 200
	distinctIDs := map[uint64]int{}
	distinctFrameTypes := map[uint64]int{}
	var sawNonEmptyGreasePayload bool

	for range runs {
		frame := newTestSettingsFrame()
		settings, trailingFrames := parseSettingsAndTrailingFrames(t, appendControlStream(nil, frame, true))

		if len(settings) != 2 {
			t.Fatalf("serialized %d settings, want the webtransport one plus a greased one: %v", len(settings), settings)
		}
		var greasedID uint64
		for _, entry := range settings {
			if entry[0] != 0x2b603742 {
				greasedID = entry[0]
			}
		}
		if greasedID == 0 {
			t.Fatalf("no greased identifier in %v", settings)
		}
		if (greasedID-0x21)%0x1f != 0 {
			t.Fatalf("greased identifier 0x%x is not 0x1f*N+0x21", greasedID)
		}
		distinctIDs[greasedID]++

		if len(trailingFrames) != 1 {
			t.Fatalf("SETTINGS is followed by %d frames, want exactly one greasing frame: %v", len(trailingFrames), trailingFrames)
		}
		frameType, payloadLen := trailingFrames[0][0], trailingFrames[0][1]
		if (frameType-0x21)%0x1f != 0 {
			t.Fatalf("greasing frame type 0x%x is not 0x1f*N+0x21", frameType)
		}
		if payloadLen > 3 {
			t.Fatalf("greasing frame carries %d payload bytes, quiche draws rand32 %% 4", payloadLen)
		}
		if payloadLen > 0 {
			sawNonEmptyGreasePayload = true
		}
		distinctFrameTypes[frameType]++
	}

	if len(distinctIDs) < runs/2 {
		t.Fatalf("only %d distinct greased identifiers over %d runs, the draw is not random", len(distinctIDs), runs)
	}
	if len(distinctFrameTypes) < runs/2 {
		t.Fatalf("only %d distinct greasing frame types over %d runs, the draw is not random", len(distinctFrameTypes), runs)
	}
	if !sawNonEmptyGreasePayload {
		t.Fatal("every greasing frame had an empty payload, the length is not drawn from rand32 % 4")
	}
}

func TestControlStreamStaysCleanWithoutGreasing(t *testing.T) {
	frame := newTestSettingsFrame()
	settings, trailingFrames := parseSettingsAndTrailingFrames(t, appendControlStream(nil, frame, false))

	if len(settings) != 1 || settings[0] != [2]uint64{0x2b603742, 1} {
		t.Fatalf("serialized %v, want only the webtransport setting", settings)
	}
	if len(trailingFrames) != 0 {
		t.Fatalf("SETTINGS is followed by %v, want nothing", trailingFrames)
	}
}
