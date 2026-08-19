package httpcommon

import (
	"fmt"
	"testing"
)

func TestOrderedHeaderKeysChromeOrder(t *testing.T) {
	header := map[string][]string{
		"Cookie":          {"a=1"},
		"User-Agent":      {"x"},
		"Accept":          {"*/*"},
		"Sec-Fetch-Site":  {"none"},
		"Accept-Encoding": {"gzip"},
		"Accept-Language": {"en"},
		"Referer":         {"https://example"},
		"X-Custom":        {"1"},
	}
	got := orderedHeaderKeys(header)
	want := []string{
		"User-Agent",
		"Accept-Language",
		"Accept",
		"Sec-Fetch-Site",
		"Referer",
		"Accept-Encoding",
		"Cookie",
		"X-Custom",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
