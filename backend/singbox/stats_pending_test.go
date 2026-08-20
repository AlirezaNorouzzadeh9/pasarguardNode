package singbox

import "testing"

// sing-box ignores the query pattern and resets every counter it holds, so the
// backend drains it once and shares out what it got. These pin the property
// that failed in practice: a poll for one kind of counter must not destroy
// another kind that nobody has read yet.
//
// The symptom was a user downloading a megabyte and being billed nothing, at
// random, depending on whether the outbound poll or the user poll ran first.

func newPending(seed map[string]int64) *statsClient {
	c := &statsClient{pending: make(map[string]int64)}
	for k, v := range seed {
		c.pending[k] = v
	}
	return c
}

func TestTakingUserCountersLeavesTheOutboundOnes(t *testing.T) {
	c := newPending(map[string]int64{
		"user>>>101>>>traffic>>>downlink":    1048576,
		"outbound>>>direct>>>traffic>>>down": 2097152,
	})

	got := c.take("user>>>", true)
	if got["user>>>101>>>traffic>>>downlink"] != 1048576 {
		t.Fatalf("user counter not returned: %v", got)
	}
	if len(got) != 1 {
		t.Fatalf("user poll returned somebody else's counters: %v", got)
	}
	// The whole point: the outbound poll has not run yet and must still find it.
	if c.pending["outbound>>>direct>>>traffic>>>down"] != 2097152 {
		t.Fatal("a user poll destroyed the outbound counter")
	}
}

func TestConsumedCountersAreNotBilledTwice(t *testing.T) {
	c := newPending(map[string]int64{"user>>>101>>>traffic>>>downlink": 1048576})

	c.take("user>>>", true)
	if got := c.take("user>>>", true); len(got) != 0 {
		t.Fatalf("counter served a second time: %v", got)
	}
}

func TestLookingWithoutConsumingKeepsTheCounter(t *testing.T) {
	c := newPending(map[string]int64{"user>>>101>>>traffic>>>downlink": 4096})

	if got := c.take("user>>>", false); got["user>>>101>>>traffic>>>downlink"] != 4096 {
		t.Fatalf("counter not reported: %v", got)
	}
	if c.pending["user>>>101>>>traffic>>>downlink"] != 4096 {
		t.Fatal("a read that was not consuming still cleared the counter")
	}
}

func TestCountersAccumulateBetweenPolls(t *testing.T) {
	// Two drains with no consumer in between must add up, not overwrite: that
	// is what makes it safe to reset sing-box on every single poll.
	c := newPending(nil)
	for _, v := range []int64{1000, 2500} {
		c.pendingMu.Lock()
		c.pending["user>>>101>>>traffic>>>downlink"] += v
		c.pendingMu.Unlock()
	}
	if got := c.take("user>>>", true)["user>>>101>>>traffic>>>downlink"]; got != 3500 {
		t.Fatalf("expected 3500 accumulated, got %d", got)
	}
}

func TestAnEmptyPrefixTakesEverything(t *testing.T) {
	c := newPending(map[string]int64{
		"user>>>101>>>traffic>>>downlink":    1,
		"outbound>>>direct>>>traffic>>>down": 2,
	})
	if got := c.take("", true); len(got) != 2 {
		t.Fatalf("expected every counter, got %v", got)
	}
	if len(c.pending) != 0 {
		t.Fatalf("pending should be empty, still holds %v", c.pending)
	}
}

// The panel decides up vs down by Stat.Type == "uplink"/"downlink" (that is
// where xray's parser puts the direction). An earlier splitStatName put the
// counter category there instead, which made every sing-box outbound byte
// count as downlink and dropped per-inbound counters entirely.
func TestSplitStatNameMatchesXrayFieldOrder(t *testing.T) {
	name, kind, link := splitStatName("inbound>>>singbox-ss>>>traffic>>>uplink")
	if name != "singbox-ss" || kind != "uplink" || link != "traffic" {
		t.Fatalf("got (%q, %q, %q), want (singbox-ss, uplink, traffic)", name, kind, link)
	}

	// A counter that is not four >>>-parts passes through under its own name.
	name, kind, link = splitStatName("weird_counter")
	if name != "weird_counter" || kind != "" || link != "" {
		t.Fatalf("unexpected passthrough: (%q, %q, %q)", name, kind, link)
	}
}
