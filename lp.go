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
	"time"
	"unsafe"

	"github.com/dustin/go-humanize"
	"golang.org/x/sys/unix"
)

// #include <unistd.h>
import "C"

func main() {
	log.SetFlags(0)
	var (
		all      = flag.Bool("all", false, "List processes from all users, not just the current user")
		full     = flag.Bool("full", false, "Shorthand for -cols 'pid,ppid,user,cmdline'")
		colsFlag = flag.String("cols", "", "List of columns to display (comma-separated)")
	)
	var f filter
	flag.Var(reFlag{&f.name}, "name", "Regular expression to match against process name")
	flag.Var(reFlag{&f.cmd}, "cmd", "Regular expression to match against the cmdline")
	flag.IntVar(&f.pid, "pid", 0, "Only list the process with this process ID")
	flag.IntVar(&f.ppid, "ppid", 0, "Only list processes with this parent PID")
	flag.IntVar(&f.pgid, "pgid", 0, "Only list processes with this process group ID")
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
including the lp process. Flags such as -pid, -name, and others filter down the
results using other criteria.

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

	needCols := cols
	if !*all {
		f.thisPID = os.Getpid()
		needCols |= colPID
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		f.user = u.Username
		needCols |= colUser
	}
	if f.name != nil {
		needCols |= colName
	}
	if f.cmd != nil {
		needCols |= colCmdline
	}
	if f.pid != 0 {
		needCols |= colPID
	}
	if f.ppid != 0 {
		needCols |= colPPID
	}
	if f.pgid != 0 {
		needCols |= colPGID
	}

	l := newLister(&f, needCols)
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
	clockTick time.Duration
	pageSize  bytesize

	needCols column
	buf      []byte
	users    map[uint32]string
	uptime   time.Duration
	filter   *filter
}

func newLister(f *filter, needCols column) *lister {
	clockTicksPerSec := C.sysconf(C._SC_CLK_TCK)
	return &lister{
		clockTick: time.Second / time.Duration(clockTicksPerSec),
		pageSize:  bytesize(os.Getpagesize()),
		needCols:  needCols,
		users:     make(map[uint32]string),
		filter:    f,
	}
}

func (l *lister) list() ([]*process, error) {
	var err error
	l.uptime, err = l.getUptime()
	if err != nil {
		return nil, err
	}
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
		ps = append(ps, p)
	}
	if l.needCols.has(colNChild | colNDesc) {
		fillChildDesc(ps)
	}
	i := 0
	for _, p := range ps {
		if l.filter.include(p) {
			ps[i] = p
			i++
		}
	}
	ps = ps[:i]
	return ps, nil
}

func (l *lister) getUptime() (time.Duration, error) {
	f, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b, err := l.readAll(f)
	if err != nil {
		return 0, err
	}
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return 0, errors.New("malformed /proc/uptime")
	}
	return time.ParseDuration(string(b[:i]) + "s")
}

type process struct {
	pid      int
	name     string
	cmdline  string
	ppid     int
	pgid     int
	rss      bytesize
	uptime   time.Duration
	utime    time.Duration
	stime    time.Duration
	cutime   time.Duration
	cstime   time.Duration
	cpuTime  time.Duration
	nthreads int32
	nfds     int64
	nchild   int64
	ndesc    int64
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
	if l.needCols.has(colCmdline) {
		if err := l.parseCmdline(&p, basePath+"/cmdline"); err != nil {
			return nil, err
		}
	}
	if l.needCols.has(colNFDs) {
		if err := l.parseFDs(&p, basePath+"/fd"); err != nil {
			return nil, err
		}
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
		case 14: // utime
			utime, err := parseUint32b(b)
			if err != nil {
				return err
			}
			p.utime = time.Duration(utime) * l.clockTick
		case 15: // stime
			stime, err := parseUint32b(b)
			if err != nil {
				return err
			}
			p.stime = time.Duration(stime) * l.clockTick
		case 16: // cutime
			cutime, err := parseUint32b(b)
			if err != nil {
				return err
			}
			p.cutime = time.Duration(cutime) * l.clockTick
		case 17: // cstime
			cstime, err := parseUint32b(b)
			if err != nil {
				return err
			}
			p.cstime = time.Duration(cstime) * l.clockTick
			p.cpuTime = p.utime + p.stime + p.cutime + p.cstime
		case 20: // num_threads
			p.nthreads, err = parseInt32b(b)
			if err != nil {
				return err
			}
		case 22: // starttime
			startTime, err := parseUint64b(b)
			if err != nil {
				return err
			}
			uptime := l.uptime - time.Duration(startTime)*l.clockTick
			if uptime < 0 {
				uptime = 0
			}
			p.uptime = uptime
		case 24: // rss
			pages, err := parseInt32b(b)
			if err != nil {
				return err
			}
			p.rss = bytesize(pages) * l.pageSize
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

func (l *lister) parseFDs(p *process, path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrPermission) {
		p.nfds = -1
		return nil
	}
	if err != nil {
		return err
	}
	p.nfds, l.buf, err = direntCount(f, l.buf)
	return err
}

func fillChildDesc(ps []*process) {
	byPID := make(map[int]*process)
	for _, p := range ps {
		byPID[p.pid] = p
	}
	for _, p := range ps {
		if parent, ok := byPID[p.ppid]; ok {
			parent.nchild++
		}
	}
	rem := ps
	for len(rem) > 0 {
		var next []*process
		for _, p := range rem {
			parent, ok := byPID[p.ppid]
			if !ok {
				continue
			}
			parent.ndesc++
			next = append(next, parent)
		}
		rem = next
	}
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

func parseUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func parseUint32b(b []byte) (uint32, error) {
	return parseUint32(unsafeString(b))
}

func parseUint64b(b []byte) (uint64, error) {
	return strconv.ParseUint(unsafeString(b), 10, 64)
}

func unsafeString(b []byte) string {
	var s string
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	sh.Data = (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
	sh.Len = len(b)
	return s
}

type filter struct {
	name *regexp.Regexp
	cmd  *regexp.Regexp
	pid  int
	ppid int
	pgid int

	thisPID int    // don't include our own PID
	user    string // only include this user
}

func (f *filter) include(p *process) bool {
	switch {
	case f.thisPID == p.pid:
		return false
	case f.user != "" && f.user != p.user:
		return false
	case f.name != nil && !f.name.MatchString(p.name):
		return false
	case f.cmd != nil && !f.cmd.MatchString(p.cmdline):
		return false
	case f.pid != 0 && f.pid != p.pid:
		return false
	case f.ppid != 0 && f.ppid != p.ppid:
		return false
	case f.ppid != 0 && f.ppid != p.ppid:
		return false
	case f.pgid != 0 && f.pgid != p.pgid:
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
	colRSS
	colUptime
	colUtime
	colStime
	colCutime
	colCstime
	colCPUTime
	colNThreads
	colNFDs
	colNChild
	colNDesc
	colCmdline
	numCols
)

type colConf struct {
	name       string
	desc       string
	rightAlign bool
}

var colConfs = map[column]colConf{
	colPID: {
		name:       "pid",
		desc:       "Process ID",
		rightAlign: true,
	},
	colPPID: {
		name:       "ppid",
		desc:       "Parent process ID",
		rightAlign: true,
	},
	colUser: {
		name: "user",
		desc: "Username of the process owner",
	},
	colName: {
		name: "name",
		desc: "Name of the command (as reported by /proc/[pid]/stat)",
	},
	colPGID: {
		name:       "pgid",
		desc:       "Process group ID",
		rightAlign: true,
	},
	colRSS: {
		name:       "rss",
		desc:       "Process resident set size (not including children)",
		rightAlign: true,
	},
	colUptime: {
		name:       "uptime",
		desc:       "How long the process has been running (wall time)",
		rightAlign: true,
	},
	colUtime: {
		name:       "utime",
		desc:       "Amount of time this process has been scheduled in user mode",
		rightAlign: true,
	},
	colStime: {
		name:       "stime",
		desc:       "Amount of time this process has been scheduled in kernel mode",
		rightAlign: true,
	},
	colCutime: {
		name:       "cutime",
		desc:       "Sum of utime for all descendents that were waited for and have exited",
		rightAlign: true,
	},
	colCstime: {
		name:       "cstime",
		desc:       "Sum of stime for all descendents that were waited for and have exited",
		rightAlign: true,
	},
	colCPUTime: {
		name:       "cputime",
		desc:       "Total CPU time as estimated by utime+stime+cutime+cstime",
		rightAlign: true,
	},
	colNThreads: {
		name:       "nthreads",
		desc:       "Number of threads in the process",
		rightAlign: true,
	},
	colNFDs: {
		name:       "nfds",
		desc:       "Number of open file descriptors",
		rightAlign: true,
	},
	colNChild: {
		name:       "nchild",
		desc:       "Number of child processes",
		rightAlign: true,
	},
	colNDesc: {
		name:       "ndesc",
		desc:       "Number of descendent processes",
		rightAlign: true,
	},
	colCmdline: {
		name: "cmdline",
		desc: "Command line for the process",
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
		{colRSS, p.rss},
		{colUptime, p.uptime},
		{colUtime, p.utime},
		{colStime, p.stime},
		{colCutime, p.cutime},
		{colCstime, p.cstime},
		{colCPUTime, p.cpuTime},
		{colNThreads, p.nthreads},
		{colNFDs, p.nfds},
		{colNChild, p.nchild},
		{colNDesc, p.ndesc},
		{colCmdline, p.cmdline},
	} {
		if cols.has(cell.col) {
			switch v := cell.v.(type) {
			case time.Duration:
				cells = append(cells, formatDuration(v))
			case int64:
				if v == -1 {
					cells = append(cells, "?")
				} else {
					cells = append(cells, strconv.FormatInt(v, 10))
				}
			default:
				cells = append(cells, fmt.Sprint(cell.v))
			}
		}
	}
	tw.append(cells)
}

type columnOpts uint

const (
	rightAlign columnOpts = 1 << iota
)

type tableWriter struct {
	termWidth int
	opts      []columnOpts
	widths    []int
	cells     [][]string
}

func newTableWriter(cols column) *tableWriter {
	n := bits.OnesCount(uint(cols))
	tw := &tableWriter{
		termWidth: termWidth(),
		opts:      make([]columnOpts, n),
		widths:    make([]int, n),
		cells:     [][]string{make([]string, n)},
	}
	i := 0
	for col := column(1); col < numCols; col <<= 1 {
		if !cols.has(col) {
			continue
		}
		cc := colConfs[col]
		var opts columnOpts
		if cc.rightAlign {
			opts |= rightAlign
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
			if tw.opts[j]&rightAlign != 0 {
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
			trim = tw.termWidth > 3 && len(b) < tw.termWidth
		}
		if trim && len(b) > tw.termWidth {
			b = b[:tw.termWidth-3]
			b = append(b, "..."...)
		}
		b = append(b, '\n')
		bw.Write(b)
	}
}

type reFlag struct {
	p **regexp.Regexp
}

func (f reFlag) Set(s string) error {
	re, err := regexp.Compile(s)
	if err != nil {
		return err
	}
	*f.p = re
	return nil
}

func (f reFlag) String() string {
	if f.p == nil || *f.p == nil {
		return ""
	}
	return (*f.p).String()
}

type bytesize int64

func (b bytesize) String() string {
	return humanize.Bytes(uint64(b))
}

func formatDuration(d time.Duration) string {
	var m time.Duration
	switch {
	case d < time.Microsecond:
		m = time.Nanosecond
	case d < 10*time.Microsecond:
		m = 10 * time.Nanosecond
	case d < 100*time.Microsecond:
		m = 100 * time.Nanosecond
	case d < time.Millisecond:
		m = time.Microsecond
	case d < 10*time.Millisecond:
		m = 10 * time.Microsecond
	case d < 100*time.Millisecond:
		m = 100 * time.Microsecond
	case d < time.Second:
		m = time.Millisecond
	case d < 10*time.Second:
		m = 10 * time.Millisecond
	case d < time.Minute:
		m = 100 * time.Millisecond
	case d < time.Hour:
		m = time.Second
	case d < 1000*time.Hour:
		m = time.Minute
	default:
		m = time.Hour
	}

	// TODO: For uptime specifically, displaying "12345h" is probably not
	// as useful as displaying a date. But getting a readable, compact
	// display is tricky.

	s := d.Round(m).String()
	if m > time.Second {
		s = strings.TrimSuffix(s, "0s")
		if m > time.Minute {
			s = strings.TrimSuffix(s, "0m")
		}
	}
	return s
}

// termWidth returns the terminal width or else 0 if stdout is not a terminal.
func termWidth() int {
	if ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ); err == nil {
		return int(ws.Col)
	}
	return 0
}
