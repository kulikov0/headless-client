package headless

import "testing"

func TestBrandListReproducesTheMeasuredChromiumHint(t *testing.T) {
	got := clientHintBrandList(151, "")
	want := `"Chromium";v="151", "Not=A?Brand";v="99"`
	if got != want {
		t.Fatalf("chromium 151 sends %q, we build %q", want, got)
	}
}

func TestBrandListPlacesTheProductBrandForChrome(t *testing.T) {
	got := clientHintBrandList(151, "Google Chrome")
	want := `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`
	if got != want {
		t.Fatalf("brand list = %q, want %q", got, want)
	}
}

func TestBrandListVariesWithTheMajorVersion(t *testing.T) {
	seen := map[string]int{}
	for majorVersion := 145; majorVersion < 160; majorVersion++ {
		seen[clientHintBrandList(majorVersion, "Google Chrome")]++
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct brand lists across 15 versions, the shuffle or the grease is stuck", len(seen))
	}
}
