package headlessclient

import (
	"strconv"

	utls "github.com/refraction-networking/utls"
)

const measuredChromeMajorVersion = 151

var measuredChromeVersion = strconv.Itoa(measuredChromeMajorVersion)

type Profile struct {
	name               string
	userAgent          string
	acceptLanguage     string
	clientHintBrands   string
	clientHintMobile   string
	clientHintPlatform string
	clientHelloID      utls.ClientHelloID
	dtlsShuffle        bool
	dtlsGREASE         bool
	dtls13Mimic        bool
}

var ChromeWindows = Profile{
	name:               "ChromeWindows",
	userAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + measuredChromeVersion + ".0.0.0 Safari/537.36",
	acceptLanguage:     "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	clientHintBrands:   clientHintBrandList(measuredChromeMajorVersion, "Google Chrome"),
	clientHintMobile:   "?0",
	clientHintPlatform: `"Windows"`,
	clientHelloID:      utls.HelloChrome_133,
	dtlsShuffle:        true,
	dtlsGREASE:         true,
}

func (p Profile) Name() string {
	return p.name
}

func (p Profile) ClientHelloID() utls.ClientHelloID {
	if p.clientHelloID.Client == "" {
		return utls.HelloChrome_Auto
	}
	return p.clientHelloID
}

func (p Profile) WithName(name string) Profile {
	p.name = name
	return p
}

func (p Profile) WithUserAgent(userAgent string) Profile {
	p.userAgent = userAgent
	return p
}

func (p Profile) WithAcceptLanguage(acceptLanguage string) Profile {
	p.acceptLanguage = acceptLanguage
	return p
}

func (p Profile) WithClientHelloID(clientHelloID utls.ClientHelloID) Profile {
	p.clientHelloID = clientHelloID
	return p
}

func (p Profile) WithDTLS13Mimicry() Profile {
	p.dtlsShuffle = false
	p.dtlsGREASE = false
	p.dtls13Mimic = true
	return p
}
