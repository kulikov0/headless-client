package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

var ja4Versions = map[uint16]string{
	0x0304: "13",
	0x0303: "12",
	0x0302: "11",
	0x0301: "10",
}

func (h *Hello) JA4() string {
	if h.IsDTLS() {
		return ""
	}

	transport := "t"
	if len(h.QUICTransportParams) > 0 {
		transport = "q"
	}

	version := h.HelloVersion
	for _, offered := range h.SupportedVersions {
		if !IsGREASE(offered) && offered > version {
			version = offered
		}
	}
	versionCode, ok := ja4Versions[version]
	if !ok {
		versionCode = "00"
	}

	serverNameCode := "i"
	if h.ServerName != "" {
		serverNameCode = "d"
	}

	alpnCode := "00"
	if len(h.ALPN) > 0 {
		first := h.ALPN[0]
		alpnCode = string(first[0]) + string(first[len(first)-1])
	}

	suites := hexList(WithoutGREASE(h.CipherSuites))
	sort.Strings(suites)

	extensions := hexList(WithoutGREASE(h.ExtensionTypes()))
	hashed := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		if extension == "0000" || extension == "0010" {
			continue
		}
		hashed = append(hashed, extension)
	}
	sort.Strings(hashed)

	signatures := hexList(h.SignatureAlgorithms)

	return fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s",
		transport, versionCode, serverNameCode,
		min(len(suites), 99), min(len(extensions), 99), alpnCode,
		ja4Hash(strings.Join(suites, ",")),
		ja4Hash(strings.Join(hashed, ",")+"_"+strings.Join(signatures, ",")))
}

func ja4Hash(value string) string {
	if value == "" || value == "_" {
		return strings.Repeat("0", 12)
	}
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:])[:12]
}

func hexList(values []uint16) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = fmt.Sprintf("%04x", value)
	}

	return out
}
