package quic

import (
	crand "crypto/rand"
	"math/rand/v2"
	"testing"

	"github.com/kulikov0/headless-client/quic/internal/ackhandler"
	"github.com/kulikov0/headless-client/quic/internal/protocol"
	"github.com/kulikov0/headless-client/quic/internal/wire"
	"github.com/kulikov0/headless-client/quic/quicvarint"
)

const chaosTestClientHelloLen = 281

func chaosTestFrames(t *testing.T, dataLength int) ([]ackhandler.Frame, []byte) {
	t.Helper()
	data := make([]byte, dataLength)
	if _, err := crand.Read(data); err != nil {
		t.Fatalf("cannot generate test data: %v", err)
	}
	original := make([]byte, dataLength)
	copy(original, data)

	return []ackhandler.Frame{{Frame: &wire.CryptoFrame{Data: data}}}, original
}

func TestChaosProtectMatchesChromeFrameCounts(t *testing.T) {
	random := rand.New(rand.NewPCG(0x5ec12ed, 0xc0ffee))
	const runs = 2000
	minCryptoFrames, maxCryptoFrames, totalCryptoFrames := 1<<30, 0, 0
	minPingFrames, maxPingFrames := 1<<30, 0
	minPaddingLeft := protocol.ByteCount(1 << 30)
	var sawNonMonotonicOffsets bool
	var runsStartingAtOffsetZero, totalPaddingRuns int

	for range runs {
		frames, original := chaosTestFrames(t, chaosTestClientHelloLen)
		frameLength := frames[0].Frame.Length(protocol.Version1)
		paddingLength := protocol.ByteCount(1200) - frameLength
		entries, ok := chaosProtect(frames, paddingLength, random)
		if !ok {
			t.Fatal("chaosProtect declined a payload with one crypto frame and padding")
		}

		reassembled := make([]byte, chaosTestClientHelloLen)
		written := make([]bool, chaosTestClientHelloLen)
		var totalLength protocol.ByteCount
		var cryptoFrames, pingFrames, singleByteCryptoFrames int
		var previousOffset, paddingBytes protocol.ByteCount
		for i, entry := range entries {
			if entry.frame == nil {
				totalLength += entry.paddingLen
				paddingBytes += entry.paddingLen
				totalPaddingRuns++
				continue
			}
			totalLength += entry.frame.Length(protocol.Version1)
			switch frame := entry.frame.(type) {
			case *wire.CryptoFrame:
				if cryptoFrames == 0 && frame.Offset == 0 {
					runsStartingAtOffsetZero++
				}
				if cryptoFrames > 0 && frame.Offset < previousOffset {
					sawNonMonotonicOffsets = true
				}
				previousOffset = frame.Offset
				cryptoFrames++
				if len(frame.Data) == 1 {
					singleByteCryptoFrames++
				}
				for j, b := range frame.Data {
					position := int(frame.Offset) + j
					if written[position] {
						t.Fatalf("byte %d covered twice, entry %d", position, i)
					}
					written[position] = true
					reassembled[position] = b
				}
			case *wire.PingFrame:
				pingFrames++
			default:
				t.Fatalf("unexpected frame type %T", entry.frame)
			}
		}

		if totalLength != frameLength+paddingLength {
			t.Fatalf("length changed: got %d, want %d", totalLength, frameLength+paddingLength)
		}
		for position, ok := range written {
			if !ok {
				t.Fatalf("byte %d never serialized", position)
			}
		}
		if string(reassembled) != string(original) {
			t.Fatal("reassembled client hello differs from the original")
		}
		if got := frames[0].Frame.(*wire.CryptoFrame); len(got.Data) != chaosTestClientHelloLen {
			t.Fatalf("input frame was mutated: data length %d", len(got.Data))
		}
		if cryptoFrames < 1+minAddedCryptoFrames && singleByteCryptoFrames == 0 {
			t.Fatalf("only %d crypto frames without a single-byte frame to explain the skipped split", cryptoFrames)
		}

		minCryptoFrames = min(minCryptoFrames, cryptoFrames)
		maxCryptoFrames = max(maxCryptoFrames, cryptoFrames)
		totalCryptoFrames += cryptoFrames
		minPingFrames = min(minPingFrames, pingFrames)
		maxPingFrames = max(maxPingFrames, pingFrames)
		minPaddingLeft = min(minPaddingLeft, paddingBytes)
	}

	if minCryptoFrames < 2 || maxCryptoFrames != 1+maxAddedCryptoFrames {
		t.Fatalf("crypto frame count range is [%d, %d], want [>=2, %d]",
			minCryptoFrames, maxCryptoFrames, 1+maxAddedCryptoFrames)
	}
	if minPaddingLeft < 100 {
		t.Fatalf("padding budget ran down to %d bytes, splits were cut short by the budget rather than by chance", minPaddingLeft)
	}
	if averageCryptoFrames := float64(totalCryptoFrames) / runs; averageCryptoFrames < 6 {
		t.Fatalf("average crypto frame count %.2f, Chrome scatters 6 to 9 chunks", averageCryptoFrames)
	}
	if minPingFrames != minAddedPingFrames || maxPingFrames != maxAddedPingFrames {
		t.Fatalf("ping frame count range is [%d, %d], want [%d, %d]",
			minPingFrames, maxPingFrames, minAddedPingFrames, maxAddedPingFrames)
	}
	if !sawNonMonotonicOffsets {
		t.Fatal("crypto offsets were always increasing, Chrome scatters them")
	}
	if runsStartingAtOffsetZero > runs/2 {
		t.Fatalf("%d of %d runs put offset 0 first, the frames are not being reordered", runsStartingAtOffsetZero, runs)
	}
	if averagePaddingRuns := float64(totalPaddingRuns) / runs; averagePaddingRuns < 3 {
		t.Fatalf("average of %.2f padding runs per packet, the padding is not spread between the frames", averagePaddingRuns)
	}
}

type chaosTestSealer struct{}

func (chaosTestSealer) Seal(dst, _ []byte, _ protocol.PacketNumber, _ []byte) []byte { return dst }

func (chaosTestSealer) EncryptHeader(_ []byte, _ *byte, _ []byte) {}

func (chaosTestSealer) Overhead() int { return 0 }

type chaosTestPacketNumberManager struct{}

func (chaosTestPacketNumberManager) PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return chaosTestPacketNumber, protocol.PacketNumberLen4
}

func (chaosTestPacketNumberManager) PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber {
	return chaosTestPacketNumber
}

const (
	chaosTestPacketNumber = protocol.PacketNumber(1)
	chaosTestPacketSize   = protocol.ByteCount(1200)
	chaosTestPaddingType  = 0
)

func chaosTestPackAndCount(t *testing.T, perspective protocol.Perspective, encLevel protocol.EncryptionLevel) (cryptoFrames, pingFrames, paddingRuns int) {
	t.Helper()
	packer := &packetPacker{
		perspective: perspective,
		pnManager:   chaosTestPacketNumberManager{},
		rand:        *rand.New(rand.NewPCG(0x9e3779b9, 0x7f4a7c15)),
	}
	frames, _ := chaosTestFrames(t, chaosTestClientHelloLen)
	packetType := protocol.PacketTypeInitial
	if encLevel == protocol.EncryptionHandshake {
		packetType = protocol.PacketTypeHandshake
	}
	header := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             packetType,
			Version:          protocol.Version1,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		PacketNumber:    chaosTestPacketNumber,
		PacketNumberLen: protocol.PacketNumberLen4,
	}
	pl := payload{frames: frames, length: frames[0].Frame.Length(protocol.Version1)}
	buffer := getPacketBuffer()
	defer buffer.Release()

	if _, err := packer.appendLongHeaderPacket(buffer, header, pl, chaosTestPacketSize-pl.length, encLevel, chaosTestSealer{}, protocol.Version1); err != nil {
		t.Fatalf("cannot pack a long header packet: %v", err)
	}
	headerBytes, err := header.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("cannot measure the serialized header: %v", err)
	}
	body := buffer.Data[len(headerBytes):]
	if protocol.ByteCount(len(body)) != chaosTestPacketSize {
		t.Fatalf("payload is %d bytes, want %d", len(body), chaosTestPacketSize)
	}

	var inPaddingRun bool
	for len(body) > 0 {
		frameType, consumed, err := quicvarint.Parse(body)
		if err != nil {
			t.Fatalf("cannot parse a frame type: %v", err)
		}
		body = body[consumed:]
		if frameType == chaosTestPaddingType {
			if !inPaddingRun {
				paddingRuns++
				inPaddingRun = true
			}
			continue
		}
		inPaddingRun = false
		switch wire.FrameType(frameType) {
		case wire.FrameTypePing:
			pingFrames++
		case wire.FrameTypeCrypto:
			_, offsetLen, err := quicvarint.Parse(body)
			if err != nil {
				t.Fatalf("cannot parse a crypto frame offset: %v", err)
			}
			body = body[offsetLen:]
			dataLength, dataLengthLen, err := quicvarint.Parse(body)
			if err != nil {
				t.Fatalf("cannot parse a crypto frame length: %v", err)
			}
			body = body[dataLengthLen+int(dataLength):]
			cryptoFrames++
		default:
			t.Fatalf("unexpected frame type 0x%x in a packed %s %s packet", frameType, perspective, encLevel)
		}
	}

	return cryptoFrames, pingFrames, paddingRuns
}

func TestPacketPackerScattersTheClientInitialCryptoFrames(t *testing.T) {
	cryptoFrames, pingFrames, paddingRuns := chaosTestPackAndCount(t, protocol.PerspectiveClient, protocol.EncryptionInitial)
	if cryptoFrames < 1+minAddedCryptoFrames-1 {
		t.Fatalf("client initial carried %d crypto frames, chaosProtect is no longer reached from appendLongHeaderPacket", cryptoFrames)
	}
	if pingFrames < minAddedPingFrames {
		t.Fatalf("client initial carried %d ping frames, want at least %d", pingFrames, minAddedPingFrames)
	}
	if paddingRuns < 2 {
		t.Fatalf("client initial carried %d padding runs, the padding is not spread between the frames", paddingRuns)
	}
}

func TestPacketPackerLeavesEveryOtherLongHeaderPacketContiguous(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		perspective protocol.Perspective
		encLevel    protocol.EncryptionLevel
	}{
		{"server initial", protocol.PerspectiveServer, protocol.EncryptionInitial},
		{"client handshake", protocol.PerspectiveClient, protocol.EncryptionHandshake},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cryptoFrames, pingFrames, _ := chaosTestPackAndCount(t, testCase.perspective, testCase.encLevel)
			if cryptoFrames != 1 || pingFrames != 0 {
				t.Fatalf("got %d crypto and %d ping frames, chaos protection must only run on client initial packets", cryptoFrames, pingFrames)
			}
		})
	}
}

func TestChaosProtectDeclinesWithoutPaddingOrCryptoData(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))

	frames, _ := chaosTestFrames(t, chaosTestClientHelloLen)
	if _, ok := chaosProtect(frames, 0, random); ok {
		t.Fatal("chaos protection ran without a padding budget")
	}

	pingOnly := []ackhandler.Frame{{Frame: &wire.PingFrame{}}}
	if _, ok := chaosProtect(pingOnly, 1000, random); ok {
		t.Fatal("chaos protection ran without a crypto frame")
	}
}
