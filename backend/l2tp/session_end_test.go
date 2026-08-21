package l2tp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pasarguard/node/pkg/stats"
)

// A ppp interface is destroyed with its session, taking the kernel counters the
// poll loop reads with it. Everything moved since the previous tick was
// therefore lost at every disconnect, and a session shorter than one tick was
// never counted at all — connect, pull a few hundred megabytes, disconnect,
// repeat, and the data limit never moves.
//
// The ip-down hook now writes the closing counters out. These pin that the poll
// loop bills them, once, against the right baseline.

func newPolled(t *testing.T, ifSeen map[string][2]int64) *L2TP {
	t.Helper()
	sessionStateDir = t.TempDir()
	sessionFinalDir = t.TempDir()
	if ifSeen == nil {
		ifSeen = map[string][2]int64{}
	}
	return &L2TP{
		config:       &Config{InboundTag: "l2tp-test"},
		statsTracker: stats.New(),
		ifSeen:       ifSeen,
		cumRx:        map[string]int64{},
		cumTx:        map[string]int64{},
		onlineIPs:    map[string]map[string]int64{},
	}
}

func writeFinal(t *testing.T, name, user, tag, ifname string, rx, tx int64) {
	t.Helper()
	body := "user=" + user + "\ntag=" + tag + "\nifname=" + ifname + "\n" +
		"rx=" + itoa(rx) + "\ntx=" + itoa(tx) + "\n"
	if err := os.WriteFile(filepath.Join(sessionFinalDir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write final record: %v", err)
	}
}

func writeSession(t *testing.T, ifname, user, tag string) {
	t.Helper()
	body := "user=" + user + "\ntunnel_ip=10.77.0.9\nclient=\ntag=" + tag + "\npid=0\nstarted=1\n"
	if err := os.WriteFile(filepath.Join(sessionStateDir, ifname), []byte(body), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestEndedSessionTailIsBilled(t *testing.T) {
	// Last tick saw 1000/9000 on ppp0; the session then moved more and ended.
	o := newPolled(t, map[string][2]int64{"ppp0": {1000, 9000}})
	writeFinal(t, "ppp0.1.100", "173", "l2tp-test", "ppp0", 1500, 12000)

	o.poll()

	if o.cumRx["173"] != 500 || o.cumTx["173"] != 3000 {
		t.Fatalf("tail billed as rx=%d tx=%d, want rx=500 tx=3000", o.cumRx["173"], o.cumTx["173"])
	}
	if _, still := o.ifSeen["ppp0"]; still {
		t.Error("settled interface kept its baseline; the next session on ppp0 would be measured against a stranger")
	}
	if left, _ := os.ReadDir(sessionFinalDir); len(left) != 0 {
		t.Errorf("final record not consumed (%d left); it would be billed again next tick", len(left))
	}
}

func TestSessionShorterThanOnePollIsBilledInFull(t *testing.T) {
	o := newPolled(t, nil)
	writeFinal(t, "ppp3.1.100", "173", "l2tp-test", "ppp3", 800, 40000)

	o.poll()

	if o.cumRx["173"] != 800 || o.cumTx["173"] != 40000 {
		t.Fatalf("billed rx=%d tx=%d, want the whole session rx=800 tx=40000 — otherwise reconnect cycling evades the data limit",
			o.cumRx["173"], o.cumTx["173"])
	}
}

func TestFinalIsSettledBeforeTheInterfaceIsReused(t *testing.T) {
	// User A left ppp0 at 1500/12000 and B is already on the recycled interface.
	// A's tail must be measured against A's own baseline, and B must start from
	// zero — the kernel counters restarted with the interface.
	o := newPolled(t, map[string][2]int64{"ppp0": {1000, 9000}})
	writeFinal(t, "ppp0.1.100", "173", "l2tp-test", "ppp0", 1500, 12000)
	writeSession(t, "ppp0", "974", "l2tp-test")

	o.poll()

	if o.cumRx["173"] != 500 || o.cumTx["173"] != 3000 {
		t.Errorf("departing user billed rx=%d tx=%d, want rx=500 tx=3000", o.cumRx["173"], o.cumTx["173"])
	}
	// ifaceBytes reads /sys for a name that does not exist here, so B's counters
	// read as zero; what matters is that B did not inherit A's baseline, which
	// would have shown up as a negative delta or a wild number.
	if o.cumRx["974"] != 0 || o.cumTx["974"] != 0 {
		t.Errorf("new occupant billed rx=%d tx=%d from a stranger's baseline", o.cumRx["974"], o.cumTx["974"])
	}
}

func TestFinalRecordOfAnotherCoreIsLeftAlone(t *testing.T) {
	// Several L2TP cores share the directory; each settles only its own.
	o := newPolled(t, nil)
	writeFinal(t, "ppp9.1.100", "555", "l2tp-other", "ppp9", 700, 7000)

	o.poll()

	if o.cumRx["555"] != 0 {
		t.Errorf("billed %d bytes belonging to another core", o.cumRx["555"])
	}
	if left, _ := os.ReadDir(sessionFinalDir); len(left) != 1 {
		t.Errorf("another core's record was consumed; that core would never bill it")
	}
}

func TestFinalBelowBaselineBillsNothing(t *testing.T) {
	// The hook falls back to pppd's link totals when the interface is already
	// gone; those count a layer lower and can come in under the last /sys read.
	o := newPolled(t, map[string][2]int64{"ppp0": {5000, 50000}})
	writeFinal(t, "ppp0.1.100", "173", "l2tp-test", "ppp0", 4000, 40000)

	o.poll()

	if o.cumRx["173"] != 0 || o.cumTx["173"] != 0 {
		t.Fatalf("billed rx=%d tx=%d for a session that appears to have gone backwards; a whole-session re-bill is worse than a lost tail",
			o.cumRx["173"], o.cumTx["173"])
	}
}

func TestTruncatedFinalRecordIsDiscarded(t *testing.T) {
	o := newPolled(t, nil)
	if err := os.WriteFile(filepath.Join(sessionFinalDir, "ppp0.1.100"), []byte("user=\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	o.poll()

	if left, _ := os.ReadDir(sessionFinalDir); len(left) != 0 {
		t.Error("unusable record kept; it would be retried on every tick forever")
	}
}
