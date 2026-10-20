package headless

import "net/http"

const (
	headerOrderKey  = "Header-Order:"
	pHeaderOrderKey = "PHeader-Order:"
)

var chromeWebTransportPseudoHeaderOrder = []string{
	":scheme",
	":method",
	":authority",
	":path",
	":protocol",
}

var chromeWebTransportHeaderOrder = []string{
	"sec-webtransport-http3-draft02",
	"origin",
}

func (p Profile) WebTransportConnectHeader(origin string) http.Header {
	header := http.Header{}
	header["User-Agent"] = nil
	header["Sec-Webtransport-Http3-Draft02"] = []string{"1"}
	header["Origin"] = []string{origin}
	header[pHeaderOrderKey] = chromeWebTransportPseudoHeaderOrder
	header[headerOrderKey] = chromeWebTransportHeaderOrder
	return header
}
