package headless

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestSecFetchSiteFollowsTheChromiumOriginRelation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		initiator string
		target    string
		want      string
	}{
		{"api on a sibling subdomain", "https://www.google.com", "https://apis.google.com/v1/discovery", "same-site"},
		{"script on a static host", "https://www.google.com", "https://www.gstatic.com/og/_/js/app.js", "cross-site"},
		{"same name under another tld", "https://www.google.com", "https://www.google.ru/", "cross-site"},
		{"ajax on one host", "https://www.google.com", "https://www.google.com/complete/search?q=x", "same-origin"},
		{"no initiator", "", "https://www.google.com/", "none"},
		{"opaque initiator", "null", "https://www.google.com/", "cross-site"},
		{"scheme mismatch", "http://www.google.com", "https://www.google.com/", "cross-site"},
		{"port only difference", "https://www.google.com:8443", "https://www.google.com/", "same-site"},
		{"explicit default port", "https://www.google.com:443", "https://www.google.com/", "same-origin"},
		{"uppercase initiator", "HTTPS://WWW.GOOGLE.COM", "https://apis.google.com/v1", "same-site"},
		{"two label suffix", "https://www.google.co.uk", "https://mail.google.co.uk/x", "same-site"},
		{"distinct registrable domains under a two label suffix", "https://google.co.uk", "https://youtube.co.uk/x", "cross-site"},
		{"private registry", "https://a.appspot.com", "https://b.appspot.com/x", "cross-site"},
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

func secFetchSitesAlongRedirectChain(t *testing.T, http2Enabled bool, header http.Header, hosts []string) []string {
	t.Helper()

	var seenMutex sync.Mutex
	var seenSites []string
	address, _ := countingTLSServer(t, http2Enabled, func(w http.ResponseWriter, r *http.Request) {
		seenMutex.Lock()
		seenSites = append(seenSites, r.Header.Get("Sec-Fetch-Site"))
		seenMutex.Unlock()
		remainingHosts := strings.Split(strings.TrimPrefix(r.URL.Path, "/chain/"), "/")
		if remainingHosts[0] == "" {
			io.WriteString(w, "ok")
			return
		}
		http.Redirect(w, r, "https://"+remainingHosts[0]+"/chain/"+strings.Join(remainingHosts[1:], "/"), http.StatusFound)
	})

	request, err := http.NewRequest(http.MethodGet, "https://"+hosts[0]+"/chain/"+strings.Join(hosts[1:], "/"), nil)
	if err != nil {
		t.Fatalf("cannot build the request: %v", err)
	}
	request.Header = header
	response, err := pooledClient(address).Do(request)
	if err != nil {
		t.Fatalf("http2=%t request through %v: %v", http2Enabled, hosts, err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()

	seenMutex.Lock()
	defer seenMutex.Unlock()

	return slices.Clone(seenSites)
}

func TestSecFetchSiteTakesTheWorstRelationAlongTheRedirectChain(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		hosts []string
		want  []string
	}{
		{"same-origin to cross-site to same-origin", []string{"example.com", "example.org", "example.com"}, []string{"same-origin", "cross-site", "cross-site"}},
		{"same-origin to same-site to same-origin", []string{"example.com", "api.example.com", "example.com"}, []string{"same-origin", "same-site", "same-site"}},
		{"cross-site to same-origin", []string{"example.org", "example.com"}, []string{"cross-site", "cross-site"}},
		{"cross-site to same-site", []string{"example.org", "api.example.com"}, []string{"cross-site", "cross-site"}},
		{"cross-site to cross-site", []string{"example.org", "example.org"}, []string{"cross-site", "cross-site"}},
		{"same-origin to same-origin", []string{"example.com", "example.com"}, []string{"same-origin", "same-origin"}},
		{"same-origin to same-site", []string{"example.com", "api.example.com"}, []string{"same-origin", "same-site"}},
		{"same-origin to cross-site", []string{"example.com", "example.org"}, []string{"same-origin", "cross-site"}},
		{"same-site to same-origin", []string{"api.example.com", "example.com"}, []string{"same-site", "same-site"}},
		{"same-site to same-site", []string{"api.example.com", "api.example.com"}, []string{"same-site", "same-site"}},
		{"same-site to cross-site", []string{"api.example.com", "example.org"}, []string{"same-site", "cross-site"}},
	} {
		for _, http2Enabled := range []bool{false, true} {
			header := ChromeWindows.Headers(DestEmpty)
			header.Set("Origin", "https://example.com")
			got := secFetchSitesAlongRedirectChain(t, http2Enabled, header, testCase.hosts)
			if !slices.Equal(got, testCase.want) {
				t.Errorf("http2=%t %s: initiator https://example.com through %v arrived as %v, chromium keeps the worst relation along the url chain and sends %v",
					http2Enabled, testCase.name, testCase.hosts, got, testCase.want)
			}
		}
	}
}

func TestSecFetchSiteStaysNoneAlongANavigationRedirect(t *testing.T) {
	for _, http2Enabled := range []bool{false, true} {
		hosts := []string{"example.com", "example.org", "example.com"}
		got := secFetchSitesAlongRedirectChain(t, http2Enabled, ChromeWindows.Headers(DestDocument), hosts)
		want := []string{"none", "none", "none"}
		if !slices.Equal(got, want) {
			t.Errorf("http2=%t a navigation without an initiator through %v arrived as %v, chromium sends %v on every hop",
				http2Enabled, hosts, got, want)
		}
	}
}
