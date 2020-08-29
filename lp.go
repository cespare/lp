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

By default, lp includes all processes belonging to the current user.
With the -all flag, lp prints processes for all users.

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
	pid     int32
	name    string
	cmdline string
	ppid    int32
	pgid    int32
	user    string
}

var errNotAProcess = errors.New("/proc dir is not a pid")

func (l *lister) loadProcess(fi os.FileInfo) (*process, error) {
	var p process
	var err error
	p.pid, err = parseInt32(fi.Name())
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
			p.ppid, err = parseInt32b(b)
			if err != nil {
				return err
			}
		case 5: // pgrp
			p.pgid, err = parseInt32b(b)
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

func parseInt32(s string) (int32, error) {
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(n), nil
}

func parseInt32b(b []byte) (int32, error) {
	var s string
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	sh.Data = (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
	sh.Len = len(b)
	return parseInt32(s)
}

func parseUint32b(b []byte) (uint32, error) {
	var s string
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	sh.Data = (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
	sh.Len = len(b)
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

type filter struct {
	user string
	name *regexp.Regexp
	cmd  *regexp.Regexp
}

func (f *filter) include(p *process) bool {
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
	for _, row := range tw.cells {
		for i, cell := range row {
			if i > 0 {
				io.WriteString(bw, pad)
			}
			w := tw.widths[i]
			if tw.opts[i]&rightAligned != 0 {
				io.WriteString(bw, strings.Repeat(" ", w-len(cell)))
				io.WriteString(bw, cell)
			} else {
				io.WriteString(bw, cell)
				if i < len(row)-1 {
					io.WriteString(bw, strings.Repeat(" ", w-len(cell)))
				}
			}
		}
		io.WriteString(bw, "\n")
	}
}
