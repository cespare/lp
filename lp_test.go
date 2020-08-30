package main

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestListerParseStat(t *testing.T) {
	dir := t.TempDir()
	const contents = `1860 (panel-6-indicat) S 1837 1689 1689 0 -1 4194304 2673 34 2 0 77 38 5 7 20 0 3 0 1971 440897536 6029 18446744073709551615 94731670310912 94731670333832 140730895617600 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0 94731672435056 94731672436756 94731700363264 140730895620536 140730895620840 140730895620840 140730895622086 0`
	statPath := filepath.Join(dir, "stat")
	if err := ioutil.WriteFile(statPath, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}

	l := newLister(nil, 0)
	l.clockTick = 10 * time.Millisecond
	l.pageSize = 4096
	l.uptime = 10 * time.Minute
	p := new(process)
	if err := l.parseStat(p, statPath); err != nil {
		t.Fatalf("parseStat: %s", err)
	}

	want := &process{
		name:     "panel-6-indicat",
		ppid:     1837,
		pgid:     1689,
		rss:      24694784,
		uptime:   9*time.Minute + 40*time.Second + 290*time.Millisecond,
		nthreads: 3,
		utime:    770 * time.Millisecond,
		stime:    380 * time.Millisecond,
		cutime:   50 * time.Millisecond,
		cstime:   70 * time.Millisecond,
		cpuTime:  1270 * time.Millisecond,
	}

	if diff := cmp.Diff(p, want, cmp.AllowUnexported(process{})); diff != "" {
		t.Errorf("parseStat gave incorrect output (-got,+want):\n%s", diff)
	}
}

func TestFillChildDesc(t *testing.T) {
	ps := []*process{
		{pid: 1, ppid: 0},
		{pid: 2, ppid: 1},
		{pid: 5, ppid: 1},
		{pid: 10, ppid: 5},
		{pid: 11, ppid: 5},
		{pid: 12, ppid: 5},
		{pid: 13, ppid: 5},
		{pid: 14, ppid: 13},
		{pid: 15, ppid: 14},
		{pid: 16, ppid: 15},
		// The graph might be disconnected since we aren't looking at
		// any kind of consistent snapshot.
		{pid: 20, ppid: 19},
		{pid: 21, ppid: 19},
	}
	fillChildDesc(ps)

	want := []*process{
		{pid: 1, ppid: 0, nchild: 2, ndesc: 9},
		{pid: 2, ppid: 1, nchild: 0, ndesc: 0},
		{pid: 5, ppid: 1, nchild: 4, ndesc: 7},
		{pid: 10, ppid: 5, nchild: 0, ndesc: 0},
		{pid: 11, ppid: 5, nchild: 0, ndesc: 0},
		{pid: 12, ppid: 5, nchild: 0, ndesc: 0},
		{pid: 13, ppid: 5, nchild: 1, ndesc: 3},
		{pid: 14, ppid: 13, nchild: 1, ndesc: 2},
		{pid: 15, ppid: 14, nchild: 1, ndesc: 1},
		{pid: 16, ppid: 15, nchild: 0, ndesc: 0},
		{pid: 20, ppid: 19, nchild: 0, ndesc: 0},
		{pid: 21, ppid: 19, nchild: 0, ndesc: 0},
	}
	if diff := cmp.Diff(ps, want, cmp.AllowUnexported(process{})); diff != "" {
		t.Errorf("fillChildDesc filled incorrectly (-got,+want):\n%s", diff)
	}
}

func TestTableWriter(t *testing.T) {
	tw := newTableWriter(colPID | colName | colPPID)
	tw.termWidth = 100
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
	tw.termWidth = 16
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
	tw.termWidth = 10 // Too small for trimming.
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

func TestFormatDuration(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
	}{
		{"145ns", "145ns"},
		{"15.0009ms", "15ms"},
		{"15.192ms", "15.2ms"},
		{"58.1234001s", "58.1s"},
		{"128.1234001s", "2m8s"},
		{"1h10m33.111s", "1h11m"},
		{"48h33s", "48h1m"},
		{"1011h45m", "1012h"},
	} {
		d, err := time.ParseDuration(tt.in)
		if err != nil {
			t.Errorf("invalid input %q", tt.in)
			continue
		}
		got := formatDuration(d)
		if got != tt.want {
			t.Errorf("formatDuration(%s): got %s; want %s", d, got, tt.want)
		}
	}
}
