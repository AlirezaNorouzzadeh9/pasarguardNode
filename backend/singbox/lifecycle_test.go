package singbox

import "testing"

// Stopping the core and cleaning up after a start that failed look the same
// from the outside and mean opposite things to the supervisor. Conflating them
// is what made a crash-restart loop give up after its first attempt: start()
// called Shutdown() when the core did not come ready, Shutdown() recorded "stay
// stopped", and the supervisor read that as its own cue to return — so a core
// whose first restart failed for a passing reason stayed dead for good.

func newLifecycleSB() *SingBox {
	return &SingBox{
		config:   &Config{inbounds: []managedInbound{{tag: "hy2", kind: credHysteria2}}},
		users:    map[string]userCredentials{},
		pushStop: make(chan struct{}),
		stats:    &statsClient{pending: map[string]int64{}},
	}
}

func TestAFailedStartDoesNotTellTheSupervisorToGiveUp(t *testing.T) {
	s := newLifecycleSB()

	s.teardown()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stopping {
		t.Fatal("cleaning up a failed start marked the core as deliberately stopped")
	}
}

func TestShutdownTellsTheSupervisorToGiveUp(t *testing.T) {
	s := newLifecycleSB()

	s.Shutdown()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.stopping {
		t.Fatal("an asked-for stop did not record that it was asked for")
	}
}

func TestShutdownWakesTheSupervisorOutOfItsBackoff(t *testing.T) {
	s := newLifecycleSB()
	stop := s.pushStop

	s.Shutdown()

	select {
	case <-stop:
	default:
		t.Fatal("pushStop was never closed, so a supervisor asleep in its backoff would wait it out")
	}
}

func TestShutdownIsSafeToCallTwice(t *testing.T) {
	// The panel stops a node it is already stopping often enough that a second
	// call closing an already-closed channel would panic the node.
	s := newLifecycleSB()
	s.Shutdown()
	s.Shutdown()
}

func TestUnreadUsageSurvivesTheCoreBeingTornDown(t *testing.T) {
	// The counters have been taken out of sing-box and not yet given to the
	// panel. A restart that rebuilt the stats client dropped them, and nobody
	// was billed for that traffic.
	s := newLifecycleSB()
	s.stats.pending["user>>>101>>>traffic>>>downlink"] = 1048576

	s.teardown()

	if got := s.stats.pending["user>>>101>>>traffic>>>downlink"]; got != 1048576 {
		t.Fatalf("usage collected but not yet reported was lost: got %d", got)
	}
}
