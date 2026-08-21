package stats

import (
	"sync"
	"testing"
)

func TestInterfaceCountersTrackerFirstSampleIsZero(t *testing.T) {
	tracker := NewInterfaceCountersTracker()

	rx, tx := tracker.Delta(100, 200, false)
	if rx != 0 || tx != 0 {
		t.Fatalf("expected zero delta on first sample, got rx=%d tx=%d", rx, tx)
	}
}

func TestInterfaceCountersTrackerNormalDelta(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(100, 200, false)

	rx, tx := tracker.Delta(130, 260, false)
	if rx != 30 || tx != 60 {
		t.Fatalf("unexpected delta, got rx=%d tx=%d want rx=30 tx=60", rx, tx)
	}
}

func TestInterfaceCountersTrackerReset(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(100, 200, false)

	rx, tx := tracker.Delta(150, 260, true)
	if rx != 50 || tx != 60 {
		t.Fatalf("unexpected reset delta, got rx=%d tx=%d want rx=50 tx=60", rx, tx)
	}

	rx, tx = tracker.Delta(170, 290, false)
	if rx != 20 || tx != 30 {
		t.Fatalf("unexpected post-reset delta, got rx=%d tx=%d want rx=20 tx=30", rx, tx)
	}
}

func TestInterfaceCountersTrackerRollbackRebases(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(200, 300, false)

	rx, tx := tracker.Delta(150, 250, false)
	if rx != 0 || tx != 0 {
		t.Fatalf("expected zero after rollback rebase, got rx=%d tx=%d", rx, tx)
	}

	rx, tx = tracker.Delta(170, 260, false)
	if rx != 20 || tx != 10 {
		t.Fatalf("unexpected delta after rollback rebase, got rx=%d tx=%d want rx=20 tx=10", rx, tx)
	}
}

func TestInterfaceCountersTrackerConcurrentSafety(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(0, 0, false)

	var wg sync.WaitGroup
	for i := 1; i <= 200; i++ {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			_, _ = tracker.Delta(v, v*2, v%25 == 0)
		}(int64(i))
	}
	wg.Wait()
}

func TestBuildInterfaceStats(t *testing.T) {
	stats := BuildInterfaceStats("wg0", "wg0", 15, 9)
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}

	if stats[0].GetLink() != "wg0" || stats[1].GetLink() != "wg0" {
		t.Fatalf("expected link=wg0 for all entries")
	}
}

// The counters these carry are the server's: rx is what it received from the
// client — the client's upload — and tx is what it sent them, their download.
// xray names those uplink and downlink, and the panel reads every backend
// through that one convention.
//
// They were reversed here, so wireguard, l2tp and openvpn reported every user
// and every node mirrored: a node serving downloads showed nearly all of it as
// upload, the opposite of an xray node beside it.
func TestInterfaceStatsUseTheXrayDirectionConvention(t *testing.T) {
	// A download-heavy client: a little up, a lot down.
	stats := BuildInterfaceStats("wg0", "interface", 1_000, 900_000)

	byType := map[string]int64{}
	for _, s := range stats {
		byType[s.GetType()] += s.GetValue()
	}

	if byType["uplink"] != 1_000 {
		t.Errorf("rx (what the client sent up) reported as uplink=%d, want 1000", byType["uplink"])
	}
	if byType["downlink"] != 900_000 {
		t.Errorf("tx (what the client pulled down) reported as downlink=%d, want 900000", byType["downlink"])
	}
	if byType["uplink"] > byType["downlink"] {
		t.Error("a download-heavy client is being reported as upload-heavy; the directions are mirrored")
	}
}

func TestInterfaceStatsOmitsADirectionWithNoTraffic(t *testing.T) {
	stats := BuildInterfaceStats("wg0", "interface", 0, 512)
	if len(stats) != 1 {
		t.Fatalf("expected only the direction that moved, got %d entries", len(stats))
	}
	if stats[0].GetType() != "downlink" || stats[0].GetValue() != 512 {
		t.Errorf("got %s=%d, want downlink=512", stats[0].GetType(), stats[0].GetValue())
	}
	if BuildInterfaceStats("wg0", "interface", 0, 0) != nil {
		t.Error("an idle interface should produce nothing")
	}
}
