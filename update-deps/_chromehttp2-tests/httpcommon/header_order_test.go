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
		"Accept",
		"Sec-Fetch-Site",
		"Referer",
		"Accept-Encoding",
		"Accept-Language",
		"Cookie",
		"X-Custom",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOrderedHeaderKeysDocumentShape(t *testing.T) {
	header := map[string][]string{
		"Accept-Language":           {"en"},
		"Accept-Encoding":           {"gzip"},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Site":            {"none"},
		"Accept":                    {"text/html"},
		"User-Agent":                {"x"},
		"Upgrade-Insecure-Requests": {"1"},
	}
	got := orderedHeaderKeys(header)
	want := []string{
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Accept-Language",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
