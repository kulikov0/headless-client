package headless

import (
	"net/http"
	"testing"
)

func TestSecFetchSiteFollowsTheChromiumOriginRelation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		initiator string
		target    string
		want      string
	}{
		{"telemost api", "https://telemost.yandex.ru", "https://cloud-api.yandex.ru/v1/telemost/conferences", "same-site"},
		{"telemost script", "https://telemost.yandex.ru", "https://yastatic.net/s3/frontend/app.js", "cross-site"},
		{"bitrix portal to slb", "https://company.bitrix24.ru", "https://slb.bitrix24.tech/rest/", "cross-site"},
		{"bitrix auth on one host", "https://www.bitrix24.net", "https://www.bitrix24.net/bitrix/services/main/ajax.php?action=x", "same-origin"},
		{"no initiator", "", "https://telemost.yandex.ru/", "none"},
		{"opaque initiator", "null", "https://telemost.yandex.ru/", "cross-site"},
		{"scheme mismatch", "http://telemost.yandex.ru", "https://telemost.yandex.ru/", "cross-site"},
		{"port only difference", "https://telemost.yandex.ru:8443", "https://telemost.yandex.ru/", "same-site"},
		{"explicit default port", "https://telemost.yandex.ru:443", "https://telemost.yandex.ru/", "same-origin"},
		{"uppercase initiator", "HTTPS://TELEMOST.YANDEX.RU", "https://cloud-api.yandex.ru/v1", "same-site"},
		{"two label suffix", "https://a.example.co.uk", "https://b.example.co.uk/x", "same-site"},
		{"distinct registrable domains under a two label suffix", "https://example.co.uk", "https://other.co.uk/x", "cross-site"},
		{"private registry", "https://a.github.io", "https://b.github.io/x", "cross-site"},
		{"one address two ports", "https://10.0.0.1:8443", "https://10.0.0.1/x", "same-site"},
		{"two addresses", "https://10.0.0.1", "https://10.0.0.2/x", "cross-site"},
	} {
		if got := SecFetchSite(testCase.initiator, testCase.target); got != testCase.want {
			t.Errorf("%s: SecFetchSite(%q, %q) = %q, chromium GetOriginRelation gives %q",
				testCase.name, testCase.initiator, testCase.target, got, testCase.want)
		}
	}
}

func TestSecFetchSiteIsRecomputedOnSend(t *testing.T) {
	for _, testCase := range []struct {
		origin string
		want   string
	}{
		{"https://example.org", "cross-site"},
		{"https://api.example.com", "same-site"},
		{"https://example.com", "same-origin"},
	} {
		for _, http2Enabled := range []bool{false, true} {
			header := http.Header{
				"Sec-Fetch-Site": {"same-site"},
				"Origin":         {testCase.origin},
			}
			got := requestHeaderSeenByServer(t, http2Enabled, header).Get("Sec-Fetch-Site")
			if got != testCase.want {
				t.Errorf("http2=%t origin %s against https://example.com/ arrived as %q, chromium sends %q; the per-dest constant in chromeDestHeaders must be recomputed on send",
					http2Enabled, testCase.origin, got, testCase.want)
			}
		}
	}
}

func TestSecFetchSiteIsNotAddedWhenTheProfileOmitsIt(t *testing.T) {
	for _, http2Enabled := range []bool{false, true} {
		header := http.Header{"Origin": {"https://example.org"}}
		if values, present := requestHeaderSeenByServer(t, http2Enabled, header)["Sec-Fetch-Site"]; present {
			t.Errorf("http2=%t the server saw Sec-Fetch-Site %v on a request that carried none; the round tripper must only overwrite, never add",
				http2Enabled, values)
		}
	}
}

func TestSecFetchSiteFallsBackToTheReferer(t *testing.T) {
	for _, http2Enabled := range []bool{false, true} {
		header := http.Header{
			"Sec-Fetch-Site": {"same-site"},
			"Referer":        {"https://example.org/page/"},
		}
		got := requestHeaderSeenByServer(t, http2Enabled, header).Get("Sec-Fetch-Site")
		if got != "cross-site" {
			t.Errorf("http2=%t a referer-only request arrived as %q, the initiator is https://example.org so chromium sends cross-site",
				http2Enabled, got)
		}
	}
}
