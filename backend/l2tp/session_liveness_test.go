package l2tp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pasarguard/node/pkg/stats"
)

// pppd killed outright — OOM, SIGKILL — never runs the ip-down hook, so its
// session record stayed behind for the life of the node. Every poll refreshed
// the user's online timestamp from it, so the panel showed them connected on a
// tunnel IP forever, and revoking them would signal a pid the kernel had long
// since given to something else.

func newLivenessL2TP(t *testing.T) *L2TP {
	t.Helper()
	sessionStateDir = t.TempDir()
	sessionFinalDir = t.TempDir()
	return &L2TP{
		config:       &Config{InboundTag: "l2tp-test"},
		statsTracker: stats.New(),
		ifSeen:       map[string][2]int64{},
		cumRx:        map[string]int64{},
		cumTx:        map[string]int64{},
		onlineIPs:    map[string]map[string]int64{},
	}
}

func writeSessionFile(t *testing.T, ifname, user string, pid int) string {
	t.Helper()
	body := "user=" + user + "\ntunnel_ip=10.77.0.9\ntag=l2tp-test\npid=" + itoa(int64(pid)) + "\nstarted=1\n"
	path := filepath.Join(sessionStateDir, ifname)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
	return path
}

// stubLiveness makes the named interfaces look alive and everything else dead.
func stubLiveness(t *testing.T, alive ...string) {
	t.Helper()
	live := map[string]bool{}
	for _, name := range alive {
		live[name] = true
	}
	previous := sessionIsAlive
	sessionIsAlive = func(s l2tpSession) bool { return live[s.ifname] }
	t.Cleanup(func() { sessionIsAlive = previous })
}

func TestDeadSessionRecordIsReaped(t *testing.T) {
	newLivenessL2TP(t)
	path := writeSessionFile(t, "ppp0", "173", 4242)
	stubLiveness(t) // nothing is alive

	sessions := readSessions()

	if len(sessions) != 0 {
		t.Fatalf("a session whose pppd is gone was still reported: %+v", sessions)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the record was left behind; the user would read as online forever")
	}
}

func TestLiveSessionRecordIsKept(t *testing.T) {
	newLivenessL2TP(t)
	writeSessionFile(t, "ppp0", "173", 4242)
	stubLiveness(t, "ppp0")

	sessions := readSessions()

	if len(sessions) != 1 || sessions[0].user != "173" {
		t.Fatalf("a live session was dropped: %+v", sessions)
	}
}

func TestReapedSessionStopsRefreshingOnlineState(t *testing.T) {
	o := newLivenessL2TP(t)
	writeSessionFile(t, "ppp0", "173", 4242)

	stubLiveness(t, "ppp0")
	o.poll()
	if len(o.onlineIPs["173"]) == 0 {
		t.Fatal("a live session should put the user online")
	}

	stubLiveness(t) // pppd died without running the hook
	o.poll()
	if len(o.onlineIPs["173"]) != 0 {
		t.Fatalf("user still shown online from a dead session: %+v", o.onlineIPs["173"])
	}
}

func TestProcessIsPppdRejectsWhatIsNotThere(t *testing.T) {
	// A pid nothing owns must never be treated as a live session: on Unix
	// os.FindProcess would hand back a usable handle regardless.
	if processIsPppd(0) {
		t.Error("pid 0 accepted as pppd")
	}
	if processIsPppd(1 << 30) {
		t.Error("an unused pid was accepted as pppd")
	}
	// This test binary is a live process that is definitely not pppd.
	if processIsPppd(os.Getpid()) {
		t.Error("a live non-pppd process was accepted as pppd — a recycled pid would be signalled")
	}
}
