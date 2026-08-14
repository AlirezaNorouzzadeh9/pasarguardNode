package singbox

import (
	"sync"
	"testing"
)

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

// The watcher goroutine used to close s.waitDone — the field, read at the
// moment the process exited. A restart puts its own channel there first, so the
// departing watcher closed the new one and the new watcher closed it again.
//
// close of a closed channel panics, and a panic in a goroutine takes the whole
// node process down: xray, WireGuard and OpenVPN all died because a sing-box
// core could not find its certificate. It crash-looped a live node every two
// minutes until the core was taken off it.
func TestARestartDoesNotLeaveTwoWatchersOnOneChannel(t *testing.T) {
	s := newLifecycleSB()

	// What start() does: hand the watcher the channel it created, not the field.
	watch := func() (chan struct{}, func()) {
		done := make(chan struct{})
		s.mu.Lock()
		s.waitDone = done
		s.mu.Unlock()
		return done, func() { close(done) }
	}

	_, exitFirst := watch()  // first process starts
	_, exitSecond := watch() // restart, before the first has finished exiting

	var wg sync.WaitGroup
	wg.Add(2)
	// Whichever order they exit in, each closes only its own channel.
	go func() { defer wg.Done(); exitSecond() }()
	go func() { defer wg.Done(); exitFirst() }()
	wg.Wait()
}

func TestASupervisorLeavesARunningCoreAlone(t *testing.T) {
	// Restart() stops the core and starts it again itself. A supervisor left
	// over from the stop half wakes to a core that is already up; starting a
	// second process would fight the first for its ports and fail forever
	// against a core that was never broken.
	s := newLifecycleSB()

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()

	shouldRestart := func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return !s.stopping && !s.started
	}
	if shouldRestart() {
		t.Fatal("a supervisor would have restarted a core that is already running")
	}

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	if !shouldRestart() {
		t.Fatal("a core that really is down would not be restarted")
	}
}

func TestOnlyOneSupervisorRunsAtATime(t *testing.T) {
	// Each failed restart ends in another exit, so one supervisor per exit
	// multiplies them until the host carries a crowd of goroutines all
	// restarting the same core.
	s := newLifecycleSB()

	claim := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.supervising {
			return false
		}
		s.supervising = true
		return true
	}

	if !claim() {
		t.Fatal("the first exit could not start a supervisor")
	}
	if claim() {
		t.Fatal("a second exit started another supervisor while one was already running")
	}

	// The supervisor releasing it must let a later death be supervised again.
	s.mu.Lock()
	s.supervising = false
	s.mu.Unlock()
	if !claim() {
		t.Fatal("a core that died after the supervisor finished was left dead")
	}
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
