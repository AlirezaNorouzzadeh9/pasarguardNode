package l2tp

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// sessionStateDir is where the pppd ip-up/ip-down hooks record one file per live
// PPP session, keyed by interface name. The hooks are the only writers; the Go
// poll loop is the only reader.
// Variables, not constants, only so tests can point them somewhere writable.
var sessionStateDir = "/run/pg-l2tp/sessions"

// sessionFinalDir holds one record per ENDED session: the ip-down hook's copy of
// the counters at teardown, which nothing else can recover once the interface is
// gone. The poll loop consumes and deletes them.
var sessionFinalDir = "/run/pg-l2tp/final"

// l2tpSession is one live PPP session (one connected device).
type l2tpSession struct {
	user     string
	ifname   string
	tunnelIP string
	clientIP string
	tag      string // owning core's inbound tag ("" from hooks written before it existed)
	pid      int
	started  int64
}

// readSessions returns every session the ip-up hook has recorded. A missing
// directory (no one connected yet) is not an error.
func readSessions() []l2tpSession {
	entries, err := os.ReadDir(sessionStateDir)
	if err != nil {
		return nil
	}
	var out []l2tpSession
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		s := parseSessionFile(filepath.Join(sessionStateDir, e.Name()), e.Name())
		if s.user != "" && s.ifname != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseSessionFile(path, ifname string) l2tpSession {
	s := l2tpSession{ifname: ifname}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "user":
			s.user = v
		case "tunnel_ip":
			s.tunnelIP = v
		case "client":
			s.clientIP = v
		case "tag":
			s.tag = v
		case "pid":
			s.pid, _ = strconv.Atoi(v)
		case "started":
			s.started, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return s
}

// finalRecord is one ended session's closing counters, written by the ip-down
// hook. rx/tx are cumulative for that session, in the same terms as ifaceBytes.
type finalRecord struct {
	path   string
	user   string
	tag    string
	ifname string
	rx     int64
	tx     int64
}

// readFinalRecords returns every record the ip-down hook has left, oldest first
// so two sessions that shared an interface are reconciled in the order they ran.
// A missing directory (nothing has disconnected yet) is not an error.
func readFinalRecords() []finalRecord {
	entries, err := os.ReadDir(sessionFinalDir)
	if err != nil {
		return nil
	}
	out := make([]finalRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(sessionFinalDir, e.Name())
		rec, ok := parseFinalRecord(path)
		if !ok {
			// Unreadable or truncated (the hook was killed mid-write): drop it
			// rather than leaving it to be retried forever.
			_ = os.Remove(path)
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func parseFinalRecord(path string) (finalRecord, bool) {
	rec := finalRecord{path: path}
	f, err := os.Open(path)
	if err != nil {
		return rec, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "user":
			rec.user = v
		case "tag":
			rec.tag = v
		case "ifname":
			rec.ifname = v
		case "rx":
			rec.rx, _ = strconv.ParseInt(v, 10, 64)
		case "tx":
			rec.tx, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return rec, rec.user != "" && rec.ifname != ""
}

// ifaceBytes reads an interface's cumulative counters. rx = bytes the server
// received from the client (the client's upload); tx = bytes sent to the client
// (its download).
func ifaceBytes(ifname string) (rx int64, tx int64) {
	base := filepath.Join("/sys/class/net", ifname, "statistics")
	rx = readCounter(filepath.Join(base, "rx_bytes"))
	tx = readCounter(filepath.Join(base, "tx_bytes"))
	return
}

func readCounter(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}
