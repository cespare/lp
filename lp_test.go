package main

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestListerParseStat(t *testing.T) {
	dir := t.TempDir()
	const contents = `1860 (panel-6-indicat) S 1837 1689 1689 0 -1 4194304 2673 34 2 0 77 38 0 0 20 0 3 0 1971 440897536 6029 18446744073709551615 94731670310912 94731670333832 140730895617600 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0 94731672435056 94731672436756 94731700363264 140730895620536 140730895620840 140730895620840 140730895622086 0`
	statPath := filepath.Join(dir, "stat")
	if err := ioutil.WriteFile(statPath, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}

	l := newLister(nil)
	p := new(process)
	if err := l.parseStat(p, statPath); err != nil {
		t.Fatalf("parseStat: %s", err)
	}

	want := &process{
		name: "panel-6-indicat",
		ppid: 1837,
		pgid: 1689,
	}

	if diff := cmp.Diff(p, want, cmp.AllowUnexported(process{})); diff != "" {
		t.Errorf("parseStat gave incorrect output (-want,+got):\n%s", diff)
	}
}

func TestTableWriter(t *testing.T) {
	oldTermWidth := termWidth
	t.Cleanup(func() { termWidth = oldTermWidth })

	tw := newTableWriter(colPID | colName | colPPID)
	tw.append([]string{"3", "123", "abc"})
	tw.append([]string{"10", "123", "d"})
	tw.append([]string{"11", "1", "uvwxyz"})

	var buf bytes.Buffer
	tw.write(&buf)
	want := `
pid  ppid  name
  3   123  abc
 10   123  d
 11     1  uvwxyz
`
	want = want[1:]
	if got := buf.String(); got != want {
		t.Errorf("got:\n\n%s\nwant:\n\n%s\n", got, want)
	}

	buf.Reset()
	termWidth = 16
	tw.write(&buf)
	want = `
pid  ppid  name
  3   123  abc
 10   123  d
 11     1  uv...
`
	want = want[1:]
	if got := buf.String(); got != want {
		t.Errorf("got:\n\n%s\nwant:\n\n%s\n", got, want)
	}

	buf.Reset()
	termWidth = 10 // Too small for trimming.
	tw.write(&buf)
	want = `
pid  ppid  name
  3   123  abc
 10   123  d
 11     1  uvwxyz
`
	want = want[1:]
	if got := buf.String(); got != want {
		t.Errorf("got:\n\n%s\nwant:\n\n%s\n", got, want)
	}
}
