package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDirentCount(t *testing.T) {
	dir := t.TempDir()
	for _, file := range []string{"a", "b", "c/d", "e", "f"} {
		path := filepath.Join(dir, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(path, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var buf []byte
	count := func() int64 {
		t.Helper()
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		var n int64
		n, buf, err = direntCount(f, buf)
		if err != nil {
			t.Fatalf("direntCount: %s", err)
		}
		return n
	}

	want := int64(5)
	if got := count(); got != want {
		t.Fatalf("direntCount: got %d; want %d", got, want)
	}
	if got := count(); got != want {
		t.Fatalf("direntCount: on second call, got %d; want %d", got, want)
	}
}
