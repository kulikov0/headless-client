package sdporder

import (
	"slices"
	"strings"
)

type Level int

const (
	LevelSession Level = iota
	LevelMedia
)

const codecBlockRank = "codec block"

var sessionOrder = []string{
	"group",
	"extmap-allow-mixed",
	"cryptex",
	"msid-semantic",
	"ice-lite",
}

var mediaOrder = []string{
	"rtcp",
	"candidate",
	"end-of-candidates",
	"ice-ufrag",
	"ice-pwd",
	"ice-options",
	"fingerprint",
	"setup",
	"mid",
	"sctp-port",
	"max-message-size",
	"sctp-init",
	"extmap-allow-mixed",
	"cryptex",
	"extmap",
	"inactive",
	"recvonly",
	"sendonly",
	"sendrecv",
	"msid",
	"rtcp-mux",
	"rtcp-rsize",
	"rtcp-xr",
	"x-google-flag",
	"remote-net-estimate",
	"sframe",
	codecBlockRank,
	"ssrc-group",
	"ssrc",
	"rid",
	"simulcast",
}

var codecBlockAttributes = []string{"rtpmap", "rtcp-fb", "fmtp", "packetization"}

var ranks = map[Level]map[string]int{
	LevelSession: buildRanks(sessionOrder),
	LevelMedia:   buildRanks(mediaOrder),
}

var unknownRanks = map[Level]int{
	LevelSession: len(sessionOrder),
	LevelMedia:   len(mediaOrder),
}

func buildRanks(order []string) map[string]int {
	byName := make(map[string]int, len(order)+len(codecBlockAttributes))
	for position, attribute := range order {
		if attribute == codecBlockRank {
			for _, codecAttribute := range codecBlockAttributes {
				byName[codecAttribute] = position
			}

			continue
		}
		byName[attribute] = position
	}

	return byName
}

func AttributeName(key string) string {
	name, _, _ := strings.Cut(key, ":")
	name, _, _ = strings.Cut(name, " ")

	return name
}

func Rank(level Level, key string) (int, bool) {
	position, known := ranks[level][AttributeName(key)]

	return position, known
}

func Unknown(level Level, keys []string) []string {
	missing := []string{}
	for _, key := range keys {
		if _, known := Rank(level, key); !known {
			name := AttributeName(key)
			if !slices.Contains(missing, name) {
				missing = append(missing, name)
			}
		}
	}

	return missing
}

func Reorder[Attribute any](level Level, attributes []Attribute, key func(Attribute) string) []Attribute {
	unknownRank := unknownRanks[level]
	rankOf := func(attribute Attribute) int {
		if position, known := Rank(level, key(attribute)); known {
			return position
		}

		return unknownRank
	}
	slices.SortStableFunc(attributes, func(first, second Attribute) int {
		return rankOf(first) - rankOf(second)
	})

	return attributes
}
