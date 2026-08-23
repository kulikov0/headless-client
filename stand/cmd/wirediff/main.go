package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/kulikov0/headlessclient/stand/internal/wire"
)

type group struct {
	transport string
	target    string
	hellos    []*wire.Hello
}

type helloField struct {
	name   string
	render func(*wire.Hello) string
}

var (
	cipherOrderField    = helloField{"cipher order", cipherOrder}
	extensionOrderField = helloField{"extension order", extensionOrder}
	orderFields         = []helloField{extensionOrderField, cipherOrderField}
)

var helloFields = []helloField{
	{"ja4", (*wire.Hello).JA4},
	{"record version", func(hello *wire.Hello) string { return prefixedHex(hello.RecordVersion) }},
	{"hello version", func(hello *wire.Hello) string { return prefixedHex(hello.HelloVersion) }},
	{"session id len", func(hello *wire.Hello) string { return strconv.Itoa(hello.SessionIDLen) }},
	{"cipher count", func(hello *wire.Hello) string { return strconv.Itoa(len(hello.CipherSuites)) }},
	cipherOrderField,
	{"extension count", func(hello *wire.Hello) string { return strconv.Itoa(len(hello.Extensions)) }},
	{"extension set", func(hello *wire.Hello) string {
		return renderHex(ascending(wire.WithoutGREASE(hello.ExtensionTypes())), 4)
	}},
	extensionOrderField,
	{"supported versions", func(hello *wire.Hello) string {
		return renderHex(wire.WithoutGREASE(hello.SupportedVersions), 4)
	}},
	{"supported groups", func(hello *wire.Hello) string {
		return renderHex(wire.WithoutGREASE(hello.SupportedGroups), 4)
	}},
	{"key share", renderKeyShare},
	{"signature algorithms", func(hello *wire.Hello) string { return renderHex(hello.SignatureAlgorithms, 4) }},
	{"alpn", func(hello *wire.Hello) string {
		if len(hello.ALPN) == 0 {
			return "-"
		}

		return strings.Join(hello.ALPN, " ")
	}},
	{"point formats", func(hello *wire.Hello) string { return renderHex(hello.PointFormats, 2) }},
	{"compression", func(hello *wire.Hello) string { return renderHex(hello.CompressionMethods, 2) }},
	{"use srtp", func(hello *wire.Hello) string { return renderHex(hello.UseSRTPProfiles, 4) }},
}

func main() {
	sni := flag.String("sni", "", "only consider hellos whose target contains this string")
	targetA := flag.String("a", "", "diff this target of the first role against -b")
	targetB := flag.String("b", "", "diff this target of the second role against -a")
	clientOnly := flag.Bool("client-only", true, "ignore server hellos")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wirediff [-sni HOST] <pcap|capture-dir>...")
		fmt.Fprintln(os.Stderr, "one capture prints a summary, two capture roles print a summary and a diff")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var paths []string
	for _, argument := range flag.Args() {
		expanded, err := expandCaptures(argument)
		if err != nil {
			fail("%v", err)
		}
		paths = append(paths, expanded...)
	}

	var roles []*roleCapture
	for _, path := range paths {
		capture, err := readCapture(roleName(path), path)
		if err != nil {
			fail("%s: %v", path, err)
		}
		roles = append(roles, capture)
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	grouped := make([]map[string]*group, len(roles))
	for i, role := range roles {
		grouped[i] = groupHellos(role, *sni, *clientOnly)
		summarize(writer, role, grouped[i])
	}
	writer.Flush()

	if len(roles) != 2 {
		return
	}

	if *targetA != "" || *targetB != "" {
		left := selectGroup(grouped[0], *targetA)
		right := selectGroup(grouped[1], *targetB)
		if left == nil {
			fail("%s has no target matching %q", roles[0].name, *targetA)
		}
		if right == nil {
			fail("%s has no target matching %q", roles[1].name, *targetB)
		}
		fmt.Printf("\ndiff %s %s %s <-> %s %s %s\n",
			roles[0].name, left.transport, left.target, roles[1].name, right.transport, right.target)
		diff(writer, left, right)
		writer.Flush()
		return
	}

	shared := commonTargets(grouped[0], grouped[1])
	if len(shared) == 0 {
		fmt.Printf("\nno target reached by both roles, pick them with -a and -b\n")
		return
	}
	for _, target := range shared {
		fmt.Printf("\ndiff %s <-> %s   %s\n", roles[0].name, roles[1].name, target)
		diff(writer, grouped[0][target], grouped[1][target])
		writer.Flush()
	}
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "wirediff: "+format+"\n", arguments...)
	os.Exit(1)
}

func groupHellos(role *roleCapture, sni string, clientOnly bool) map[string]*group {
	groups := map[string]*group{}
	for _, observed := range role.observations {
		if clientOnly && observed.hello.Kind != wire.HelloTLSClient && observed.hello.Kind != wire.HelloDTLSClient {
			continue
		}
		if sni != "" && !strings.Contains(observed.target, sni) {
			continue
		}
		key := observed.transport + " " + observed.target
		existing, known := groups[key]
		if !known {
			existing = &group{transport: observed.transport, target: observed.target}
			groups[key] = existing
		}
		existing.hellos = append(existing.hellos, observed.hello)
	}

	return groups
}

func summarize(writer *tabwriter.Writer, role *roleCapture, groups map[string]*group) {
	fmt.Fprintf(writer, "role %s\t%s\t%d tcp flows\t%d udp datagrams\n",
		role.name, role.path, role.tcpFlows, role.udpDatagrams)
	if len(groups) == 0 {
		fmt.Fprintf(writer, "  no client hellos\t\t\t\n")
		return
	}
	for _, key := range sortedKeys(groups) {
		current := groups[key]
		fmt.Fprintf(writer, "  %s\t%s\t%d hellos\t%s\n",
			current.transport, current.target, len(current.hellos),
			strings.Join(distinctValues(current.hellos, (*wire.Hello).JA4), " "))
		for _, field := range orderFields {
			fmt.Fprintf(writer, "    %s\t%d distinct of %d\t%s\t\n",
				field.name, len(distinctValues(current.hellos, field.render)), len(current.hellos),
				orderVerdict(current.hellos, field.render))
		}
	}
}

func orderVerdict(hellos []*wire.Hello, key func(*wire.Hello) string) string {
	switch {
	case len(hellos) < 2:
		return "unknown"
	case len(distinctValues(hellos, key)) > 1:
		return "shuffled"
	}

	return "stable"
}

func extensionOrder(hello *wire.Hello) string {
	return renderHex(wire.WithoutGREASE(hello.ExtensionTypes()), 4)
}

func cipherOrder(hello *wire.Hello) string {
	return renderHex(wire.WithoutGREASE(hello.CipherSuites), 4)
}

func selectGroup(groups map[string]*group, pattern string) *group {
	var best *group
	for _, key := range sortedKeys(groups) {
		if !strings.Contains(key, pattern) {
			continue
		}
		if best == nil || len(groups[key].hellos) > len(best.hellos) {
			best = groups[key]
		}
	}

	return best
}

func distinctValues(hellos []*wire.Hello, key func(*wire.Hello) string) []string {
	seen := map[string]bool{}
	var values []string
	for _, hello := range hellos {
		value := key(hello)
		if seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}

	return values
}

func diff(writer *tabwriter.Writer, left, right *group) {
	for _, field := range helloFields {
		report(writer, field.name, field.render(left.hellos[0]), field.render(right.hellos[0]))
	}
	for _, field := range orderFields {
		report(writer, field.name+" stability",
			orderVerdict(left.hellos, field.render), orderVerdict(right.hellos, field.render))
	}
}

func report(writer *tabwriter.Writer, field, left, right string) {
	if left == right {
		fmt.Fprintf(writer, "  %s\tSAME\t%s\n", field, left)
		return
	}
	fmt.Fprintf(writer, "  %s\tDIFF\t%s\n", field, left)
	fmt.Fprintf(writer, "  \t\t%s\n", right)
}

func commonTargets(left, right map[string]*group) []string {
	var shared []string
	for _, key := range sortedKeys(left) {
		if _, ok := right[key]; ok {
			shared = append(shared, key)
		}
	}

	return shared
}

func sortedKeys(groups map[string]*group) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

func renderHex[Value uint8 | uint16](values []Value, width int) string {
	if len(values) == 0 {
		return "-"
	}
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%0*x", width, value)
	}

	return strings.Join(parts, " ")
}

func prefixedHex(value uint16) string {
	return fmt.Sprintf("0x%04x", value)
}

func ascending(values []uint16) []uint16 {
	sorted := append([]uint16(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	return sorted
}

func renderKeyShare(hello *wire.Hello) string {
	var parts []string
	for i, group := range hello.KeyShareGroups {
		if wire.IsGREASE(group) {
			continue
		}
		parts = append(parts, fmt.Sprintf("%04x/%d", group, hello.KeyShareLengths[i]))
	}
	if len(parts) == 0 {
		return "-"
	}

	return strings.Join(parts, " ")
}
