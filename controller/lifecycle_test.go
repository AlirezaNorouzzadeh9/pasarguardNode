package controller

import (
	"context"
	"testing"

	"github.com/pasarguard/node/common"
)

// stubBackend is a Backend that does nothing but remember whether it was shut
// down, which is all these tests need to observe.
type stubBackend struct {
	shutdownCalls int
}

func (b *stubBackend) Started() bool   { return true }
func (b *stubBackend) Version() string { return "test" }
func (b *stubBackend) Logs() <-chan string {
	ch := make(chan string)
	close(ch)
	return ch
}
func (b *stubBackend) Restart() error { return nil }
func (b *stubBackend) Shutdown()      { b.shutdownCalls++ }

func (b *stubBackend) SyncUser(context.Context, *common.User) error                { return nil }
func (b *stubBackend) SyncUsers(context.Context, []*common.User) error             { return nil }
func (b *stubBackend) UpdateUsers(context.Context, []*common.User) error           { return nil }
func (b *stubBackend) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }

func (b *stubBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return nil, nil
}
func (b *stubBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return nil, nil
}
func (b *stubBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, nil
}
func (b *stubBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return nil, nil
}
func (b *stubBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return nil, nil
}

func newTestController(cores map[backendKey]*stubBackend) *Controller {
	c := New(nil)
	for key, b := range cores {
		c.backends[key] = b
	}
	return c
}

// Disconnect is what a plain Start runs before bringing the node up, so it has
// to leave nothing behind — a core that survived would keep serving users the
// new connection never asked for.
func TestDisconnectStopsEveryCore(t *testing.T) {
	de := &stubBackend{}
	us := &stubBackend{}
	c := newTestController(map[backendKey]*stubBackend{
		{typ: common.BackendType_WIREGUARD, instance: "wgde"}: de,
		{typ: common.BackendType_WIREGUARD, instance: "wgus"}: us,
	})

	c.Disconnect()

	if de.shutdownCalls != 1 || us.shutdownCalls != 1 {
		t.Fatalf("expected both cores shut down once, got %d and %d", de.shutdownCalls, us.shutdownCalls)
	}
	if len(c.backends) != 0 {
		t.Fatalf("expected no cores left after disconnect, got %d", len(c.backends))
	}
	if c.Backend() != nil {
		t.Fatal("a disconnected node must report no backend")
	}
}

// The additive path never calls Disconnect, so cores already up keep running.
func TestCoresSurviveWhenDisconnectIsNotCalled(t *testing.T) {
	de := &stubBackend{}
	c := newTestController(map[backendKey]*stubBackend{
		{typ: common.BackendType_WIREGUARD, instance: "wgde"}: de,
	})

	c.NewRequest()

	if de.shutdownCalls != 0 {
		t.Fatalf("an additive start must not stop a running core, got %d shutdowns", de.shutdownCalls)
	}
	if c.Backend() == nil {
		t.Fatal("the running core should still be reachable")
	}
}

// Additive is only meaningful once something is running; the field defaults to
// false so an ordinary Start keeps behaving exactly as it did before.
func TestAdditiveDefaultsToFalse(t *testing.T) {
	if (&common.Backend{}).GetAdditive() {
		t.Fatal("a Start request without the flag must not be treated as additive")
	}
}
