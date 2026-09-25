package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/net/http2"

	"github.com/kulikov0/headless-client/stand/internal/wire"
)

type tcpFlow struct {
	reverse string
	target  string
}

type sessionObservation struct {
	session *wire.Session
	target  string
}

type sessionGroup struct {
	protocol string
	target   string
	sessions []*wire.Session
}

type sessionField struct {
	name   string
	render func(*wire.Session) string
}

var sessionFields = []sessionField{
	{"akamai", (*wire.Session).Akamai},
	{"settings", renderSettings},
	{"window update", func(session *wire.Session) string {
		if session.Protocol != wire.ProtocolHTTP2 {
			return "-"
		}
		return strconv.FormatUint(uint64(session.WindowUpdate), 10)
	}},
	{"priority frames", func(session *wire.Session) string {
		return renderPriorities(session.Priorities)
	}},
	{"request line", func(session *wire.Session) string {
		if line := firstRequest(session).RequestLine; line != "" {
			return line
		}
		return "-"
	}},
	{"headers priority", func(session *wire.Session) string {
		if priority := firstRequest(session).Priority; priority != nil {
			return renderPriorities([]wire.HTTP2Priority{*priority})
		}
		return "-"
	}},
	{"pseudo-header order", func(session *wire.Session) string {
		return renderNames(firstRequest(session).Headers, true)
	}},
	{"header order", func(session *wire.Session) string {
		return renderNames(firstRequest(session).Headers, false)
	}},
}

func (c *roleCapture) decodeSessions(streams *wire.Streams, flows map[string]tcpFlow, keys wire.Keys) {
	c.skipped = map[string]int{}
	for _, flowKey := range streams.Keys() {
		clientStream := streams.Stream(flowKey)
		clientHello, err := wire.ParseHello(clientStream)
		if err != nil || clientHello.Kind != wire.HelloTLSClient {
			continue
		}

		handshakeSecret := keys.Secret(wire.ClientHandshake, clientHello.Random)
		trafficSecret := keys.Secret(wire.ClientTraffic, clientHello.Random)
		masterSecret := keys.Secret(wire.MasterSecret, clientHello.Random)
		if (handshakeSecret == nil || trafficSecret == nil) && masterSecret == nil {
			c.skipped["no secrets"]++
			continue
		}
		serverHello, err := wire.ParseHello(streams.Stream(flows[flowKey].reverse))
		if err != nil || serverHello.Kind != wire.HelloTLSServer {
			c.skipped["no server hello"]++
			continue
		}
		var data []byte
		if masterSecret != nil {
			data, err = wire.Decrypt12(clientStream, serverHello.CipherSuites[0], masterSecret, clientHello.Random, serverHello.Random)
		} else {
			data, err = wire.Decrypt13(clientStream, serverHello.CipherSuites[0], handshakeSecret, trafficSecret)
		}
		if len(data) == 0 {
			if err != nil {
				c.skipped["decrypt failed"]++
			} else {
				c.skipped["no application data"]++
			}
			continue
		}
		session, err := wire.ParseSession(data)
		if err != nil {
			c.skipped["not http"]++
			continue
		}

		target := flows[flowKey].target
		if clientHello.ServerName != "" {
			target = clientHello.ServerName
		}
		c.sessions = append(c.sessions, sessionObservation{session: session, target: target})
	}
}

func groupSessions(role *roleCapture, sni string) map[string]*sessionGroup {
	groups := map[string]*sessionGroup{}
	for _, observed := range role.sessions {
		if sni != "" && !strings.Contains(observed.target, sni) {
			continue
		}
		key := observed.session.Protocol + " " + observed.target
		existing, known := groups[key]
		if !known {
			existing = &sessionGroup{protocol: observed.session.Protocol, target: observed.target}
			groups[key] = existing
		}
		existing.sessions = append(existing.sessions, observed.session)
	}
	return groups
}

func summarizeSessions(writer *tabwriter.Writer, role *roleCapture, groups map[string]*sessionGroup) {
	total := len(role.sessions)
	var skipped []string
	if !role.keysFound {
		skipped = append(skipped, "no key log")
	}
	for _, reason := range sortedKeys(role.skipped) {
		total += role.skipped[reason]
		skipped = append(skipped, fmt.Sprintf("%s %d", reason, role.skipped[reason]))
	}
	if total == 0 {
		return
	}
	fmt.Fprintf(writer, "  tls\tdecrypted %d of %d connections\t%s\t\n",
		len(role.sessions), total, strings.Join(skipped, ", "))
	for _, key := range sortedKeys(groups) {
		current := groups[key]
		values := map[string]bool{}
		var akamai []string
		for _, session := range current.sessions {
			if value := session.Akamai(); !values[value] {
				values[value] = true
				akamai = append(akamai, value)
			}
		}
		fmt.Fprintf(writer, "  %s\t%s\t%d connections\t%s\n",
			current.protocol, current.target, len(current.sessions), strings.Join(akamai, " "))
	}
}

func selectSessionGroup(groups map[string]*sessionGroup, pattern string) *sessionGroup {
	var best *sessionGroup
	for _, key := range sortedKeys(groups) {
		if !strings.Contains(key, pattern) {
			continue
		}
		if best == nil || len(groups[key].sessions) > len(best.sessions) {
			best = groups[key]
		}
	}
	return best
}

func diffSessions(writer *tabwriter.Writer, left, right *sessionGroup) {
	leftSession, rightSession := left.sessions[0], right.sessions[0]
	for _, field := range sessionFields {
		report(writer, field.name, field.render(leftSession), field.render(rightSession))
	}

	leftHeaders := firstRequest(leftSession).Headers
	rightHeaders := firstRequest(rightSession).Headers
	for _, name := range headerNames(leftHeaders, rightHeaders) {
		report(writer, "header "+name, headerValue(leftHeaders, name), headerValue(rightHeaders, name))
	}
}

func firstRequest(session *wire.Session) wire.Request {
	if len(session.Requests) == 0 {
		return wire.Request{}
	}
	return session.Requests[0]
}

func headerNames(left, right []wire.HeaderField) []string {
	seen := map[string]bool{}
	var names []string
	for _, field := range append(append([]wire.HeaderField(nil), left...), right...) {
		if seen[field.Name] || strings.EqualFold(field.Name, "cookie") {
			continue
		}
		seen[field.Name] = true
		names = append(names, field.Name)
	}
	return names
}

func headerValue(headers []wire.HeaderField, name string) string {
	var values []string
	for _, field := range headers {
		if field.Name == name {
			values = append(values, field.Value)
		}
	}
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func renderSettings(session *wire.Session) string {
	if len(session.Settings) == 0 {
		return "-"
	}
	parts := make([]string, len(session.Settings))
	for i, setting := range session.Settings {
		parts[i] = fmt.Sprintf("%s=%d", http2.SettingID(setting.ID), setting.Value)
	}
	return strings.Join(parts, " ")
}

func renderPriorities(priorities []wire.HTTP2Priority) string {
	if len(priorities) == 0 {
		return "-"
	}
	parts := make([]string, len(priorities))
	for i, priority := range priorities {
		parts[i] = fmt.Sprintf("stream=%d dep=%d exclusive=%t weight=%d",
			priority.StreamID, priority.StreamDep, priority.Exclusive, int(priority.Weight)+1)
	}
	return strings.Join(parts, ", ")
}

func renderNames(headers []wire.HeaderField, pseudo bool) string {
	var names []string
	for _, field := range headers {
		if strings.HasPrefix(field.Name, ":") == pseudo {
			names = append(names, field.Name)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, " ")
}
