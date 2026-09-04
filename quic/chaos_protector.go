package quic

import (
	"math/rand/v2"

	"github.com/kulikov0/headless-client/quic/internal/ackhandler"
	"github.com/kulikov0/headless-client/quic/internal/protocol"
	"github.com/kulikov0/headless-client/quic/internal/wire"
	"github.com/kulikov0/headless-client/quic/quicvarint"
)

const (
	minAddedCryptoFrames = 2
	maxAddedCryptoFrames = 10
	minAddedPingFrames   = 2
	maxAddedPingFrames   = 10
)

type chaosEntry struct {
	frame      wire.Frame
	paddingLen protocol.ByteCount
}

func minCryptoFrameSize(offset, dataLength protocol.ByteCount) protocol.ByteCount {
	return protocol.ByteCount(1 + quicvarint.Len(uint64(offset)) + quicvarint.Len(uint64(dataLength)))
}

func chaosProtect(frames []ackhandler.Frame, paddingLen protocol.ByteCount, random *rand.Rand) ([]chaosEntry, bool) {
	if paddingLen <= 0 || len(frames) == 0 {
		return nil, false
	}

	entries := make([]chaosEntry, 0, len(frames)+maxAddedCryptoFrames+maxAddedPingFrames)
	var hasCryptoFrame bool
	var lowestOffset, highestEnd protocol.ByteCount
	for _, f := range frames {
		cryptoFrame, ok := f.Frame.(*wire.CryptoFrame)
		if !ok {
			entries = append(entries, chaosEntry{frame: f.Frame})
			continue
		}
		end := cryptoFrame.Offset + protocol.ByteCount(len(cryptoFrame.Data))
		if !hasCryptoFrame {
			lowestOffset = cryptoFrame.Offset
			highestEnd = end
		} else {
			lowestOffset = min(lowestOffset, cryptoFrame.Offset)
			highestEnd = max(highestEnd, end)
		}
		hasCryptoFrame = true
		entries = append(entries, chaosEntry{frame: &wire.CryptoFrame{Offset: cryptoFrame.Offset, Data: cryptoFrame.Data}})
	}
	if !hasCryptoFrame {
		return nil, false
	}

	remainingPadding := paddingLen
	maxSplitOverhead := minCryptoFrameSize(highestEnd, highestEnd-lowestOffset)
	numAddedCryptoFrames := minAddedCryptoFrames + random.Uint64N(maxAddedCryptoFrames+1-minAddedCryptoFrames)
	for range numAddedCryptoFrames {
		if remainingPadding < maxSplitOverhead {
			break
		}
		frameToSplit, ok := entries[random.IntN(len(entries))].frame.(*wire.CryptoFrame)
		if !ok || len(frameToSplit.Data) <= 1 {
			continue
		}
		oldOverhead := minCryptoFrameSize(frameToSplit.Offset, protocol.ByteCount(len(frameToSplit.Data)))
		keptDataLength := 1 + random.IntN(len(frameToSplit.Data)-1)
		newOffset := frameToSplit.Offset + protocol.ByteCount(keptDataLength)
		newData := frameToSplit.Data[keptDataLength:]
		frameToSplit.Data = frameToSplit.Data[:keptDataLength]
		entries = append(entries, chaosEntry{frame: &wire.CryptoFrame{Offset: newOffset, Data: newData}})
		remainingPadding -= minCryptoFrameSize(newOffset, protocol.ByteCount(len(newData)))
		remainingPadding -= minCryptoFrameSize(frameToSplit.Offset, protocol.ByteCount(keptDataLength))
		remainingPadding += oldOverhead
	}

	if remainingPadding > 0 {
		numPingFrames := minAddedPingFrames + random.Uint64N(maxAddedPingFrames+1-minAddedPingFrames)
		if protocol.ByteCount(numPingFrames) > remainingPadding {
			numPingFrames = uint64(remainingPadding)
		}
		for range numPingFrames {
			entries = append(entries, chaosEntry{frame: &wire.PingFrame{}})
		}
		remainingPadding -= protocol.ByteCount(numPingFrames)
	}

	spread := make([]chaosEntry, 0, 2*len(entries)+1)
	for _, entry := range entries {
		paddingInThisSlot := protocol.ByteCount(random.Uint64N(uint64(remainingPadding) + 1))
		if paddingInThisSlot > 0 {
			spread = append(spread, chaosEntry{paddingLen: paddingInThisSlot})
			remainingPadding -= paddingInThisSlot
		}
		spread = append(spread, entry)
	}
	if remainingPadding > 0 {
		spread = append(spread, chaosEntry{paddingLen: remainingPadding})
	}

	for i := len(spread) - 1; i > 0; i-- {
		j := random.IntN(i + 1)
		spread[i], spread[j] = spread[j], spread[i]
	}
	return spread, true
}
