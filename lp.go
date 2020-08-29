package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/bits"
	"os"
	"os/user"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	var (
		all      = flag.Bool("all", false, "List processes from all users, not just the current user")
		nameRE   = flag.String("name", "", "Regular expression to match against process name")
		cmdRE    = flag.String("cmd", "", "Regular expression to match against the cmdline")
		full     = flag.Bool("full", false, "Shorthand for -cols 'pid,ppid,user,cmdline'")
		colsFlag = flag.String("cols", "", "List of columns to display (comma-separated)")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `lp: list processes

Usage:

  lp [flags]

The flags are:

`)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, `
lp prints out a table listing processes. The first row contains column headers
and then each subsequent row corresponds to a process.

By default, lp includes all processes belonging to the current user except for
the lp process itself. With the -all flag, lp prints all processes for all users,
including the lp process.

The default set of columns is just pid and process name. A larger set of
commonly-used columns is enabled by using -full. The set of columns may be
customized using -cols 'col1,col2,...'. The full set of available columns is:

`)
		printAllColumns()
		fmt.Fprintln(os.Stderr)
	}
	flag.Parse()

	var cols column
	switch {
	case *colsFlag != "" && *full:
		log.Fatal("-full and -cols are mutually exclusive")
	case *colsFlag != "":
		for _, colName := range strings.Split(*colsFlag, ",") {
			colName = strings.TrimSpace(colName)
			col, ok := colNames[colName]
			if !ok {
				log.Fatalf("Unknown -col: %q", colName)
			}
			cols |= col
		}
	case *full:
		cols = colPID | colPPID | colUser | colCmdline
	default:
		cols = colPID | colName
	}

	f := new(filter)
	if !*all {
		f.thisPID = os.Getpid()
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		f.user = u.Username
	}
	if *nameRE != "" {
		var err error
		f.name, err = regexp.Compile(*nameRE)
		if err != nil {
			log.Fatalln("Bad -name regexp:", err)
		}
	}
	if *cmdRE != "" {
		var err error
		f.cmd, err = regexp.Compile(*cmdRE)
		if err != nil {
			log.Fatalln("Bad -cmd regexp:", err)
		}
	}

	l := newLister(f)
	ps, err := l.list()
	if err != nil {
		log.Fatal(err)
	}

	tw := newTableWriter(cols)
	defer tw.write(os.Stdout)
	for _, p := range ps {
		p.write(tw, cols)
	}
}

type lister struct {
	buf    []byte
	users  map[uint32]string
	filter *filter
}

func newLister(f *filter) *lister {
	return &lister{
		users:  make(map[uint32]string),
		filter: f,
	}
}

func (l *lister) list() ([]*process, error) {
	f, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fis, err := f.Readdir(0)
	if err != nil {
		return nil, err
	}
	var ps []*process
	for _, fi := range fis {
		p, err := l.loadProcess(fi)
		if err == errNotAProcess {
			continue
		}
		if err != nil {
			return nil, err
		}
		if l.filter.include(p) {
			ps = append(ps, p)
		}
	}
	return ps, nil
}

type process struct {
	pid      int
	name     string
	cmdline  string
	ppid     int
	pgid     int
	nthreads int32
	user     string
}

var errNotAProcess = errors.New("/proc dir is not a pid")

func (l *lister) loadProcess(fi os.FileInfo) (*process, error) {
	var p process
	var err error
	p.pid, err = strconv.Atoi(fi.Name())
	if err != nil {
		return nil, errNotAProcess
	}

	uid := fi.Sys().(*syscall.Stat_t).Uid
	p.user = l.getUser(uid)

	basePath := "/proc/" + fi.Name()
	if err := l.parseStat(&p, basePath+"/stat"); err != nil {
		return nil, err
	}
	if err := l.parseCmdline(&p, basePath+"/cmdline"); err != nil {
		return nil, err
	}

	return &p, nil
}

func (l *lister) getUser(uid uint32) string {
	if name, ok := l.users[uid]; ok {
		return name
	}
	var name string
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	l.users[uid] = name
	return name
}

func (l *lister) parseStat(p *process, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := l.readAll(f)
	if err != nil {
		return err
	}

	for col := 1; ; col++ {
		for stat[0] == ' ' {
			stat = stat[1:]
		}
		if col == 2 { // comm
			if stat[0] != '(' {
				return errors.New("malformed /stat")
			}
			i := bytes.LastIndexByte(stat, ')')
			p.name = string(stat[1:i])
			stat = stat[i+1:]
			continue
		}

		i := bytes.IndexByte(stat, ' ')
		b := stat[:i]
		var err error
		stat = stat[i:]
		switch col {
		case 4: // ppid
			p.ppid, err = parseIntb(b)
			if err != nil {
				return err
			}
		case 5: // pgrp
			p.pgid, err = parseIntb(b)
			if err != nil {
				return err
			}
		case 20: // num_threads
			p.nthreads, err = parseInt32b(b)
			if err != nil {
				return err
			}
			// Done
			return nil
		}
	}
}

var nullReplacer = strings.NewReplacer("\x00", " ")

func (l *lister) parseCmdline(p *process, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	cmdline, err := l.readAll(f)
	if err != nil {
		return err
	}
	p.cmdline = strings.TrimSpace(nullReplacer.Replace(string(cmdline)))
	return nil
}

// readAll attempts to use a single ReadAt to get the entire contents in a
// single syscall and falls back to ioutil.ReadAll otherwise.
func (l *lister) readAll(f *os.File) ([]byte, error) {
	l.buf = l.buf[:cap(l.buf)]
	if len(l.buf) > 0 {
		n, err := f.ReadAt(l.buf, 0)
		if err == nil || err != io.EOF {
			return l.buf[:n], err
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

func parseIntb(b []byte) (int, error) {
	return strconv.Atoi(unsafeString(b))
}

func parseInt32(s string) (int32, error) {
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(n), nil
}

func parseInt32b(b []byte) (int32, error) {
	return parseInt32(unsafeString(b))
}

func parseUint32b(b []byte) (uint32, error) {
	n, err := strconv.ParseUint(unsafeString(b), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func parseInt64b(b []byte) (int64, error) {
	return strconv.ParseInt(unsafeString(b), 10, 64)
}

func unsafeString(b []byte) string {
	var s string
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	sh.Data = (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
	sh.Len = len(b)
	return s
}

type filter struct {
	thisPID int            // don't include our own PID
	user    string         // only include this user
	name    *regexp.Regexp // only include processes matching this name
	cmd     *regexp.Regexp // only include processes matching this cmdline
}

func (f *filter) include(p *process) bool {
	if f.thisPID == p.pid {
		return false
	}
	if f.user != "" && f.user != p.user {
		return false
	}
	if f.name != nil && !f.name.MatchString(p.name) {
		return false
	}
	if f.cmd != nil && !f.cmd.MatchString(p.cmdline) {
		return false
	}
	return true
}

type column uint

const (
	colPID column = 1 << iota
	colPPID
	colUser
	colName
	colPGID
	colNThreads
	colCmdline
	numCols
)

type colConf struct {
	name   string
	desc   string
	string bool
}

var colConfs = map[column]colConf{
	colPID: {
		name: "pid",
		desc: "Process ID",
	},
	colPPID: {
		name: "ppid",
		desc: "Parent process ID",
	},
	colUser: {
		name:   "user",
		desc:   "Username of the process owner",
		string: true,
	},
	colName: {
		name:   "name",
		desc:   "Name of the command (as reported by /proc/[pid]/stat)",
		string: true,
	},
	colPGID: {
		name: "pgid",
		desc: "Process group ID",
	},
	colNThreads: {
		name: "nthreads",
		desc: "Number of threads in the process",
	},
	colCmdline: {
		name:   "cmdline",
		desc:   "Command line for the process",
		string: true,
	},
}

func printAllColumns() {
	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for col := column(1); col < numCols; col <<= 1 {
		cc := colConfs[col]
		fmt.Fprintf(tw, "  %s\t%s\t\n", cc.name, cc.desc)
	}
	tw.Flush()
}

var colNames = make(map[string]column)

func init() {
	for col := column(1); col < numCols; col <<= 1 {
		colNames[colConfs[col].name] = col
	}
}

func (c column) String() string {
	return colConfs[c].name
}

func (c column) has(col column) bool {
	return c&col != 0
}

func (p *process) write(tw *tableWriter, cols column) {
	var cells []string
	for _, cell := range []struct {
		col column
		v   interface{}
	}{
		{colPID, p.pid},
		{colPPID, p.ppid},
		{colUser, p.user},
		{colName, p.name},
		{colPGID, p.pgid},
		{colNThreads, p.nthreads},
		{colCmdline, p.cmdline},
	} {
		if cols.has(cell.col) {
			cells = append(cells, fmt.Sprint(cell.v))
		}
	}
	tw.append(cells)
}

type columnOpts uint

const (
	rightAligned columnOpts = 1 << iota
)

type tableWriter struct {
	opts   []columnOpts
	widths []int
	cells  [][]string
}

func newTableWriter(cols column) *tableWriter {
	n := bits.OnesCount(uint(cols))
	tw := &tableWriter{
		opts:   make([]columnOpts, n),
		widths: make([]int, n),
		cells:  [][]string{make([]string, n)},
	}
	i := 0
	for col := column(1); col < numCols; col <<= 1 {
		if !cols.has(col) {
			continue
		}
		cc := colConfs[col]
		var opts columnOpts
		if !cc.string {
			opts |= rightAligned
		}
		tw.opts[i] = opts
		tw.widths[i] = len(cc.name)
		tw.cells[0][i] = cc.name
		i++
	}
	return tw
}

func (tw *tableWriter) append(cells []string) {
	if len(cells) != len(tw.opts) {
		panic("tableWriter.append called with unexpected number of columns")
	}
	for i, cell := range cells {
		if len(cell) > tw.widths[i] {
			tw.widths[i] = len(cell)
		}
	}
	tw.cells = append(tw.cells, cells)
}

const pad = "  "

func (tw *tableWriter) write(w io.Writer) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	trim := false
	var b []byte
	for i, row := range tw.cells {
		b = b[:0]
		for j, cell := range row {
			if j > 0 {
				b = append(b, pad...)
			}
			w := tw.widths[j]
			if tw.opts[j]&rightAligned != 0 {
				for k := len(cell); k < w; k++ {
					b = append(b, ' ')
				}
				b = append(b, cell...)
			} else {
				b = append(b, cell...)
				if j < len(row)-1 {
					for k := len(cell); k < w; k++ {
						b = append(b, ' ')
					}
				}
			}
		}
		// If we're writing to a terminal, trim very long lines.
		// (These usually occur because we're emitting cmdline.)
		// If we don't trim, it's hard to read the tabular output.
		// First, decide whether to trim. If the terminal is so narrow
		// (or the number of columns is so large) that we can't even
		// print all the headers, then give up on trimming since the
		// trimmed output will probably be too confusing if it doesn't
		// include the requested columns.
		if i == 0 {
			trim = termWidth > 3 && len(b) < termWidth
		}
		if trim && len(b) > termWidth {
			b = b[:termWidth-3]
			b = append(b, "..."...)
		}
		b = append(b, '\n')
		bw.Write(b)
	}
}

// termWidth is the terminal width, or zero if stdout is not a terminal.
var termWidth int

func init() {
	if ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ); err == nil {
		termWidth = int(ws.Col)
	}
}
