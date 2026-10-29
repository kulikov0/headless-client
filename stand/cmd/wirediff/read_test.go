package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestExpandCapturesSkipsLoopbackPcaps(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"browser.pcap", "browser.loopback.pcap", "probe.pcap", "probe.loopback.pcap", "probe.keys"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	paths, err := expandCaptures(directory)
	if err != nil {
		t.Fatalf("expandCaptures: %v", err)
	}
	want := []string{filepath.Join(directory, "browser.pcap"), filepath.Join(directory, "probe.pcap")}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
}

func TestExpandCapturesKeepsAnExplicitLoopbackPcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser.loopback.pcap")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	paths, err := expandCaptures(path)
	if err != nil {
		t.Fatalf("expandCaptures: %v", err)
	}
	if !slices.Equal(paths, []string{path}) {
		t.Fatalf("paths = %v, want %v", paths, []string{path})
	}
}
