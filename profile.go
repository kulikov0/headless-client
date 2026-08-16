package headlessclient

type Profile struct {
	name              string
	userAgent         string
	acceptLanguage    string
	dtlsShuffle       bool
	dtlsGREASE        bool
	dtlsMimicChrome13 bool
}

var ChromeWindows = Profile{
	name:           "ChromeWindows",
	userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	acceptLanguage: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	dtlsShuffle:    true,
	dtlsGREASE:     true,
}

func (p Profile) Name() string {
	return p.name
}

func (p Profile) WithDTLSMimicChrome13() Profile {
	p.dtlsShuffle = false
	p.dtlsGREASE = false
	p.dtlsMimicChrome13 = true
	return p
}
