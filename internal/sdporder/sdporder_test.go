package sdporder

import (
	"slices"
	"testing"
)

func TestAttributeNameHandlesEveryPionKeyShape(t *testing.T) {
	cases := map[string]string{
		"extmap:1 urn:ietf:params:rtp-hdrext:toffset": "extmap",
		"sendrecv":              "sendrecv",
		"ssrc":                  "ssrc",
		"sctp-port:5000":        "sctp-port",
		"msid:- 8bedc2b0":       "msid",
		"end-of-candidates":     "end-of-candidates",
		"fingerprint":           "fingerprint",
		"rtcp-fb":               "rtcp-fb",
		"group:BUNDLE 0 1":      "group",
		"msid-semantic: WMS":    "msid-semantic",
		"rtcp:9 IN IP4 0.0.0.0": "rtcp",
	}
	for key, want := range cases {
		if got := AttributeName(key); got != want {
			t.Fatalf("AttributeName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestReorderMediaProducesTheChromeOrder(t *testing.T) {
	ours := []string{
		"setup:actpass",
		"mid:1",
		"ice-ufrag:5EG4",
		"ice-pwd:725",
		"rtcp-mux",
		"rtcp-rsize",
		"rtpmap:96 VP8/90000",
		"extmap:2 http://example",
		"ssrc-group:FID 1 2",
		"ssrc",
		"msid:- 8bedc2b0",
		"sendrecv",
		"fingerprint",
		"rtcp:9 IN IP4 0.0.0.0",
		"ice-options:trickle",
	}
	want := []string{
		"rtcp:9 IN IP4 0.0.0.0",
		"ice-ufrag:5EG4",
		"ice-pwd:725",
		"ice-options:trickle",
		"fingerprint",
		"setup:actpass",
		"mid:1",
		"extmap:2 http://example",
		"sendrecv",
		"msid:- 8bedc2b0",
		"rtcp-mux",
		"rtcp-rsize",
		"rtpmap:96 VP8/90000",
		"ssrc-group:FID 1 2",
		"ssrc",
	}

	got := Reorder(LevelMedia, slices.Clone(ours), func(key string) string { return key })
	if !slices.Equal(got, want) {
		t.Fatalf("media order is\n%v\nwant\n%v", got, want)
	}
}

func TestReorderKeepsTheCodecBlockInterleaved(t *testing.T) {
	codecBlock := []string{
		"rtpmap:96 VP8/90000",
		"rtcp-fb:96 goog-remb",
		"rtcp-fb:96 transport-cc",
		"rtpmap:97 rtx/90000",
		"fmtp:97 apt=96",
		"rtpmap:102 H264/90000",
		"rtcp-fb:102 nack",
		"fmtp:102 level-asymmetry-allowed=1",
	}
	ours := append([]string{"ssrc", "mid:1"}, codecBlock...)

	got := Reorder(LevelMedia, slices.Clone(ours), func(key string) string { return key })

	start := slices.Index(got, codecBlock[0])
	if start < 0 || !slices.Equal(got[start:start+len(codecBlock)], codecBlock) {
		t.Fatalf("the codec block was broken up, a single rank per codec attribute is what keeps rtpmap, rtcp-fb and fmtp interleaved per payload type:\n%v", got)
	}
	if slices.Index(got, "mid:1") > start {
		t.Fatal("mid must sort before the codec block")
	}
	if slices.Index(got, "ssrc") < start {
		t.Fatal("ssrc must sort after the codec block")
	}
}

func TestReorderSessionProducesTheChromeOrder(t *testing.T) {
	ours := []string{"msid-semantic: WMS", "extmap-allow-mixed", "group:BUNDLE 0 1"}
	want := []string{"group:BUNDLE 0 1", "extmap-allow-mixed", "msid-semantic: WMS"}

	got := Reorder(LevelSession, slices.Clone(ours), func(key string) string { return key })
	if !slices.Equal(got, want) {
		t.Fatalf("session order is %v, want %v", got, want)
	}
}

func TestUnknownAttributesSortLastAndAreReported(t *testing.T) {
	ours := []string{"content:speaker,main", "ssrc", "mid:1", "x-invented"}

	got := Reorder(LevelMedia, slices.Clone(ours), func(key string) string { return key })
	want := []string{"mid:1", "ssrc", "content:speaker,main", "x-invented"}
	if !slices.Equal(got, want) {
		t.Fatalf("unknown attributes must keep their relative order at the end, got %v want %v", got, want)
	}

	missing := Unknown(LevelMedia, ours)
	if !slices.Equal(missing, []string{"content", "x-invented"}) {
		t.Fatalf("Unknown reported %v", missing)
	}
}
