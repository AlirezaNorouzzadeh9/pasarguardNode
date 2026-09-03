package singbox

import (
	"testing"

	"github.com/pasarguard/node/backend/singbox/statsapi"
)

func stat(name string, value int64) *statsapi.Stat {
	return &statsapi.Stat{Name: name, Value: value}
}

func newFolder() *statsClient {
	return &statsClient{pending: make(map[string]int64), baseline: make(map[string]int64)}
}

// The phantom-drain: a name's counter is not cleared when its user is removed,
// so a user created again under the same name inherits the departed holder's
// cumulative total. Reading cumulatively and baselining first sight WITHOUT
// billing means that total is never charged to whoever the name belongs to now.
func TestReusedNameIsNotBilledTheOldTotal(t *testing.T) {
	c := newFolder()
	const name = "user>>>feri>>>traffic>>>downlink"

	c.fold([]*statsapi.Stat{stat(name, 20<<30)}) // 20 GiB already on the counter
	if got := c.take("user>>>", true)[name]; got != 0 {
		t.Fatalf("re-created user billed the old total: %d bytes", got)
	}

	// Only real new traffic after that point is billed.
	c.fold([]*statsapi.Stat{stat(name, (20<<30)+5000)})
	if got := c.take("user>>>", true)[name]; got != 5000 {
		t.Fatalf("expected 5000 of new traffic, got %d", got)
	}
}

// Ordinary growth of a live counter is billed as the delta since the last read.
func TestGrowthIsBilledAsDelta(t *testing.T) {
	c := newFolder()
	const name = "user>>>alice>>>traffic>>>uplink"
	c.fold([]*statsapi.Stat{stat(name, 1000)}) // first sight -> baseline only
	c.fold([]*statsapi.Stat{stat(name, 4000)}) // +3000
	c.fold([]*statsapi.Stat{stat(name, 4500)}) // +500
	if got := c.take("user>>>", true)[name]; got != 3500 {
		t.Fatalf("expected 3500 total delta, got %d", got)
	}
}

// A counter that drops below its baseline means sing-box restarted (counters
// back to zero); the value it holds now is fresh traffic, billed in full.
func TestRestartBillsTheNewValue(t *testing.T) {
	c := newFolder()
	const name = "user>>>bob>>>traffic>>>downlink"
	c.fold([]*statsapi.Stat{stat(name, 9000)})  // first sight -> baseline 9000
	c.fold([]*statsapi.Stat{stat(name, 12000)}) // +3000
	c.fold([]*statsapi.Stat{stat(name, 700)})   // restart: counter reset, bill 700
	if got := c.take("user>>>", true)[name]; got != 3700 {
		t.Fatalf("expected 3000+700=3700, got %d", got)
	}
}

// A user poll and an outbound poll both drive collect/fold; one kind's growth
// must never destroy or double-count another kind. (Cumulative reads make this
// automatic, but pin it.)
func TestFoldKeepsKindsSeparate(t *testing.T) {
	c := newFolder()
	u := "user>>>101>>>traffic>>>downlink"
	o := "outbound>>>direct>>>traffic>>>downlink"
	c.fold([]*statsapi.Stat{stat(u, 100), stat(o, 200)}) // baseline both
	c.fold([]*statsapi.Stat{stat(u, 1100), stat(o, 700)})
	got := c.take("user>>>", true)
	if got[u] != 1000 {
		t.Fatalf("user delta wrong: %d", got[u])
	}
	if c.pending[o] != 500 {
		t.Fatalf("outbound counter lost or wrong: %d", c.pending[o])
	}
}
