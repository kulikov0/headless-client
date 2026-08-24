package headlessclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	http1RequestSource = "internal/chromehttp1/request.go"
	http2RequestSource = "internal/chromehttp2/internal/httpcommon/request.go"
	http2VendorPatch   = "update-deps/chromehttp2-fingerprint.patch"
)

func headerOrderFromSource(t *testing.T, path, variableName string) []string {
	t.Helper()

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var order []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		valueSpec, ok := node.(*ast.ValueSpec)
		if !ok || len(valueSpec.Names) != 1 || valueSpec.Names[0].Name != variableName || len(valueSpec.Values) != 1 {
			return true
		}
		composite, ok := valueSpec.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range composite.Elts {
			literal, ok := element.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote %s in %s: %v", literal.Value, path, unquoteErr)
			}
			order = append(order, value)
		}

		return false
	})
	if len(order) == 0 {
		t.Fatalf("%s has no %s table", path, variableName)
	}

	return order
}

func headerOrderFromPatch(t *testing.T, path, variableName string) []string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var order []string
	collecting := false
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "+") {
			continue
		}
		added := strings.TrimSpace(strings.TrimPrefix(line, "+"))
		if strings.HasPrefix(added, "var "+variableName+" ") {
			collecting = true
			continue
		}
		if !collecting {
			continue
		}
		if added == "}" {
			break
		}
		value, unquoteErr := strconv.Unquote(strings.TrimSuffix(added, ","))
		if unquoteErr != nil {
			t.Fatalf("unquote %q in %s: %v", added, path, unquoteErr)
		}
		order = append(order, value)
	}
	if len(order) == 0 {
		t.Fatalf("%s has no %s table", path, variableName)
	}

	return order
}

func loweredHeaderNames(names []string) []string {
	lowered := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			lowered = append(lowered, strings.ToLower(name))
		}
	}

	return lowered
}

var headerOrderTables = []struct {
	shape         string
	http1Variable string
	http2Variable string
	sharedMinimum int
}{
	{"subresource", "chromeHTTP1HeaderOrder", "chromeHeaderOrder", 10},
	{"navigation", "chromeHTTP1NavigationHeaderOrder", "chromeNavigationHeaderOrder", 8},
}

func TestSharedHeadersKeepTheSameRelativeOrder(t *testing.T) {
	for _, table := range headerOrderTables {
		http1Order := loweredHeaderNames(headerOrderFromSource(t, http1RequestSource, table.http1Variable))
		http2Order := loweredHeaderNames(headerOrderFromSource(t, http2RequestSource, table.http2Variable))

		sharedInHTTP1 := make([]string, 0, len(http1Order))
		for _, name := range http1Order {
			if slices.Contains(http2Order, name) {
				sharedInHTTP1 = append(sharedInHTTP1, name)
			}
		}
		if len(sharedInHTTP1) < table.sharedMinimum {
			t.Fatalf("%s tables share only %d headers, they no longer overlap enough to compare", table.shape, len(sharedInHTTP1))
		}

		sharedInHTTP2 := make([]string, 0, len(sharedInHTTP1))
		for _, name := range http2Order {
			if slices.Contains(sharedInHTTP1, name) {
				sharedInHTTP2 = append(sharedInHTTP2, name)
			}
		}
		if !slices.Equal(sharedInHTTP1, sharedInHTTP2) {
			t.Fatalf("%s headers carried by both tables are ordered differently, one table was re-measured without the other\n http1: %v\n http2: %v",
				table.shape, sharedInHTTP1, sharedInHTTP2)
		}
	}
}

func TestVendorPatchCarriesTheGeneratedHeaderOrder(t *testing.T) {
	for _, table := range headerOrderTables {
		generated := headerOrderFromSource(t, http2RequestSource, table.http2Variable)
		patched := headerOrderFromPatch(t, http2VendorPatch, table.http2Variable)

		if !slices.Equal(generated, patched) {
			t.Fatalf("%s would revert the %s order on the next regeneration\n file:  %v\n patch: %v",
				http2VendorPatch, table.shape, generated, patched)
		}
	}
}

func TestStoredVendorTestsMatchTheGeneratedOnes(t *testing.T) {
	pairs := [][2]string{
		{"internal/chromehttp2/chrome_fingerprint_test.go", "update-deps/_chromehttp2-tests/chrome_fingerprint_test.go"},
		{"internal/chromehttp2/internal/httpcommon/header_order_test.go", "update-deps/_chromehttp2-tests/httpcommon/header_order_test.go"},
	}

	for _, pair := range pairs {
		generated, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatalf("read %s: %v", pair[0], err)
		}
		stored, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatalf("read %s: %v", pair[1], err)
		}
		if string(generated) != string(stored) {
			t.Fatalf("%s differs from %s, the next regeneration would restore the stored copy", pair[0], pair[1])
		}
	}
}
