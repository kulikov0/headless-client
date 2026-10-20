package headless

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	secFetchSiteNone       = "none"
	secFetchSiteSameOrigin = "same-origin"
	secFetchSiteSameSite   = "same-site"
	secFetchSiteCrossSite  = "cross-site"
)

var networkSchemeDefaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
	"ws":    "80",
	"wss":   "443",
	"ftp":   "21",
}

var secFetchSiteDistance = map[string]int{
	secFetchSiteSameOrigin: 0,
	secFetchSiteSameSite:   1,
	secFetchSiteCrossSite:  2,
}

func SecFetchSite(initiator, target string) string {
	if initiator == "" {
		return secFetchSiteNone
	}
	initiatorURL, initiatorErr := url.Parse(initiator)
	targetURL, targetErr := url.Parse(target)
	if initiatorErr != nil || targetErr != nil {
		return secFetchSiteCrossSite
	}
	if !hasNetworkHost(initiatorURL) || !hasNetworkHost(targetURL) {
		return secFetchSiteCrossSite
	}

	switch {
	case sameOrigin(initiatorURL, targetURL):
		return secFetchSiteSameOrigin
	case sameSite(initiatorURL, targetURL):
		return secFetchSiteSameSite
	default:
		return secFetchSiteCrossSite
	}
}

func hasNetworkHost(parsed *url.URL) bool {
	return parsed.Scheme != "" && parsed.Hostname() != ""
}

func originScheme(parsed *url.URL) string {
	return strings.ToLower(parsed.Scheme)
}

func originHost(parsed *url.URL) string {
	return strings.ToLower(parsed.Hostname())
}

func originPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}

	return networkSchemeDefaultPorts[originScheme(parsed)]
}

func sameOrigin(initiator, target *url.URL) bool {
	return originScheme(initiator) == originScheme(target) &&
		originHost(initiator) == originHost(target) &&
		originPort(initiator) == originPort(target)
}

func sameSite(initiator, target *url.URL) bool {
	if originScheme(initiator) != originScheme(target) {
		return false
	}
	if originHost(initiator) == originHost(target) {
		return true
	}
	if _, standard := networkSchemeDefaultPorts[originScheme(initiator)]; !standard {
		return false
	}
	targetSite, targetErr := publicsuffix.EffectiveTLDPlusOne(originHost(target))
	if targetErr != nil || targetSite == "" {
		return false
	}
	initiatorSite, initiatorErr := publicsuffix.EffectiveTLDPlusOne(originHost(initiator))
	if initiatorErr != nil || initiatorSite == "" {
		return false
	}

	return initiatorSite == targetSite
}

func secFetchSiteForRequest(request *http.Request) string {
	if request.URL == nil {
		return secFetchSiteCrossSite
	}

	redirectChain := []*http.Request{request}
	for redirect := request.Response; redirect != nil && redirect.Request != nil; redirect = redirect.Request.Response {
		redirectChain = append(redirectChain, redirect.Request)
	}
	initiator := requestInitiator(redirectChain[len(redirectChain)-1])
	if initiator == "" {
		return secFetchSiteNone
	}

	worstSite := secFetchSiteSameOrigin
	for _, hop := range redirectChain {
		site := SecFetchSite(initiator, hop.URL.String())
		if secFetchSiteDistance[site] > secFetchSiteDistance[worstSite] {
			worstSite = site
		}
	}

	return worstSite
}

func requestInitiator(request *http.Request) string {
	if origin := request.Header.Get("Origin"); origin != "" {
		return origin
	}
	referer, err := url.Parse(request.Header.Get("Referer"))
	if err == nil && hasNetworkHost(referer) {
		return referer.Scheme + "://" + referer.Host
	}

	return ""
}
