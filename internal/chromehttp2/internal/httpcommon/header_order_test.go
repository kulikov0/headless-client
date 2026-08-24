package httpcommon

import (
	"context"
	"fmt"
	"net/url"
	"testing"
)

func encodedHeaderNames(t *testing.T, request Request) []string {
	t.Helper()

	var names []string
	_, err := EncodeHeaders(context.Background(), EncodeHeadersParam{Request: request}, func(name, value string) {
		names = append(names, name)
	})
	if err != nil {
		t.Fatalf("encode headers: %v", err)
	}

	return names
}

func TestEncodeHeadersLeadsWithTheChromePseudoHeaderOrder(t *testing.T) {
	target, err := url.Parse("https://api.example.com/v1/items")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	names := encodedHeaderNames(t, Request{
		URL:                 target,
		Method:              "POST",
		Host:                "api.example.com",
		ActualContentLength: 2,
		Header: map[string][]string{
			"User-Agent":   {"x"},
			"Content-Type": {"application/json"},
			"Accept":       {"*/*"},
		},
	})

	want := []string{":method", ":authority", ":scheme", ":path", "content-length"}
	if len(names) < len(want) {
		t.Fatalf("only %d headers encoded: %v", len(names), names)
	}
	if fmt.Sprint(names[:len(want)]) != fmt.Sprint(want) {
		t.Fatalf("leading headers = %v, want %v, go sends :authority first and content-length last",
			names[:len(want)], want)
	}
}

func TestEncodeHeadersPutsPriorityLast(t *testing.T) {
	target, err := url.Parse("https://api.example.com/v1/items")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	names := encodedHeaderNames(t, Request{
		URL:    target,
		Method: "GET",
		Host:   "api.example.com",
		Header: map[string][]string{
			"User-Agent":                {"x"},
			"Accept":                    {"*/*"},
			"Priority":                  {"u=1, i"},
			"X-Telemost-Client-Version": {"1.2.3"},
		},
	})

	if last := names[len(names)-1]; last != "priority" {
		t.Fatalf("last header = %q, chrome appends priority after every regular header: %v", last, names)
	}
}

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

func TestOrderedHeaderKeysKeepsTheHintsAroundUserAgentOnSubresources(t *testing.T) {
	header := map[string][]string{
		"Sec-Ch-Ua-Platform": {`"Windows"`},
		"User-Agent":         {"x"},
		"Sec-Ch-Ua":          {`"Chromium";v="151"`},
		"Content-Type":       {"application/json"},
		"Sec-Ch-Ua-Mobile":   {"?0"},
		"Accept":             {"*/*"},
		"Origin":             {"https://example"},
		"Sec-Fetch-Site":     {"same-site"},
		"Priority":           {"u=1, i"},
	}
	got := orderedHeaderKeys(header)
	want := []string{
		"Sec-Ch-Ua-Platform",
		"User-Agent",
		"Sec-Ch-Ua",
		"Content-Type",
		"Sec-Ch-Ua-Mobile",
		"Accept",
		"Origin",
		"Sec-Fetch-Site",
		"Priority",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOrderedHeaderKeysLeadsWithTheHintsOnNavigations(t *testing.T) {
	header := map[string][]string{
		"Accept-Language":           {"en"},
		"Sec-Ch-Ua-Platform":        {`"Windows"`},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Ch-Ua":                 {`"Chromium";v="151"`},
		"User-Agent":                {"x"},
		"Sec-Ch-Ua-Mobile":          {"?0"},
		"Accept":                    {"text/html"},
		"Upgrade-Insecure-Requests": {"1"},
		"Priority":                  {"u=0, i"},
	}
	got := orderedHeaderKeys(header)
	want := []string{
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Dest",
		"Accept-Language",
		"Priority",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOrderedHeaderKeysKeepsPriorityAfterAppHeaders(t *testing.T) {
	header := map[string][]string{
		"User-Agent":                {"x"},
		"Accept":                    {"*/*"},
		"Cookie":                    {"a=1"},
		"Priority":                  {"u=1, i"},
		"Client-Instance-Id":        {"abc"},
		"X-Telemost-Client-Version": {"1.2.3"},
	}
	got := orderedHeaderKeys(header)
	want := []string{
		"User-Agent",
		"Accept",
		"Cookie",
		"Client-Instance-Id",
		"X-Telemost-Client-Version",
		"Priority",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v, chrome appends priority after every regular header", got, want)
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
