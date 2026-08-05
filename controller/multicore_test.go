package controller

import (
	"context"
	"testing"

	"github.com/pasarguard/node/common"
)

// Two WireGuard cores are told apart by their interface name, so a node can run
// several at once. Without this they would share a key and the second would
// simply replace the first.
func TestBackendInstanceIDSeparatesWireGuardCores(t *testing.T) {
	de := backendInstanceID(common.BackendType_WIREGUARD, `{"interface_name":"wgde","listen_port":51820}`)
	us := backendInstanceID(common.BackendType_WIREGUARD, `{"interface_name":"wgus","listen_port":51821}`)

	if de != "wgde" || us != "wgus" {
		t.Fatalf("interface names not used as instance ids: %q, %q", de, us)
	}
	if (backendKey{typ: common.BackendType_WIREGUARD, instance: de}) ==
		(backendKey{typ: common.BackendType_WIREGUARD, instance: us}) {
		t.Fatal("two wireguard cores must not collide on one key")
	}
}

// Xray stays unkeyed: one process serves every inbound, so a second xray core
// is meant to replace the first rather than run beside it.
func TestXrayCoresStillReplaceEachOther(t *testing.T) {
	a := backendInstanceID(common.BackendType_XRAY, `{"inbounds":[{"tag":"a"}]}`)
	b := backendInstanceID(common.BackendType_XRAY, `{"inbounds":[{"tag":"b"}]}`)

	if a != "" || b != "" {
		t.Fatalf("xray should not be keyed by instance, got %q and %q", a, b)
	}
	if (backendKey{typ: common.BackendType_XRAY, instance: a}) !=
		(backendKey{typ: common.BackendType_XRAY, instance: b}) {
		t.Fatal("two xray cores must map to the same key")
	}
}

// OpenVPN cores are keyed by inbound tag, so a node can run more than one —
// each is its own process with its own port and client subnet.
func TestOpenVPNCoresAreKeyedByInboundTag(t *testing.T) {
	udp := backendInstanceID(common.BackendType_OPENVPN, `{"inbound_tag":"ovpn-udp","port":1194}`)
	tcp := backendInstanceID(common.BackendType_OPENVPN, `{"inbound_tag":"ovpn-tcp","port":443}`)

	if udp != "ovpn-udp" || tcp != "ovpn-tcp" {
		t.Fatalf("inbound tags not used as instance ids: %q, %q", udp, tcp)
	}
	if (backendKey{typ: common.BackendType_OPENVPN, instance: udp}) ==
		(backendKey{typ: common.BackendType_OPENVPN, instance: tcp}) {
		t.Fatal("two openvpn cores must not collide on one key")
	}
	// A config with no tag cannot be told apart, so it has to replace by type
	// rather than silently start a second server on the same port.
	if got := backendInstanceID(common.BackendType_OPENVPN, `{"port":1194}`); got != "" {
		t.Fatalf("expected empty instance id when inbound_tag is missing, got %q", got)
	}
}

// Different protocols never collide, even if their instance ids match.
func TestDifferentProtocolsNeverCollide(t *testing.T) {
	xray := backendKey{typ: common.BackendType_XRAY, instance: "same"}
	wg := backendKey{typ: common.BackendType_WIREGUARD, instance: "same"}

	if xray == wg {
		t.Fatal("cores of different types must never share a key")
	}
}

// A malformed config must fall back to replace-by-type rather than inventing an
// instance and quietly starting a duplicate core on the same port.
func TestUnparseableConfigFallsBackToReplaceByType(t *testing.T) {
	if got := backendInstanceID(common.BackendType_WIREGUARD, "not json at all"); got != "" {
		t.Fatalf("expected empty instance id for a broken config, got %q", got)
	}
	if got := backendInstanceID(common.BackendType_WIREGUARD, `{"listen_port":51820}`); got != "" {
		t.Fatalf("expected empty instance id when interface_name is missing, got %q", got)
	}
}

// The controller starts with no cores and reports nothing running, rather than
// handing back an empty composite that looks alive.
func TestBackendIsNilUntilACoreStarts(t *testing.T) {
	c := New(nil)

	if c.Backend() != nil {
		t.Fatal("a controller with no cores must report no backend")
	}
	if c.backends == nil {
		t.Fatal("the backend map should be initialised by New")
	}
}

// A plain Start re-declares the node's whole core set, so a core the panel has
// stopped sending must be torn down. Without this it kept running — and kept
// holding its port — until the container restarted.
func TestPlainStartRetiresCoresTheePanelNoLongerSends(t *testing.T) {
	c := New(nil)
	first := &fakeBackend{}
	second := &fakeBackend{}
	c.backends[backendKey{typ: common.BackendType_WIREGUARD, instance: "wgde1"}] = first
	c.backends[backendKey{typ: common.BackendType_WIREGUARD, instance: "wgde2"}] = second

	c.retireFor(&common.Backend{Type: common.BackendType_XRAY, Additive: false})

	if len(c.backends) != 0 {
		t.Fatalf("a plain Start must clear every core, %d left", len(c.backends))
	}
	if !first.stopped || !second.stopped {
		t.Fatal("retired cores must be shut down, not just dropped from the map")
	}
}

// An additive Start is the panel adding one more core to a node it is already
// connected to; the cores already up must survive it.
func TestAdditiveStartLeavesTheOtherCoresRunning(t *testing.T) {
	c := New(nil)
	keep := &fakeBackend{}
	replace := &fakeBackend{}
	c.backends[backendKey{typ: common.BackendType_WIREGUARD, instance: "wgde1"}] = keep
	c.backends[backendKey{typ: common.BackendType_WIREGUARD, instance: "wgde2"}] = replace

	c.retireFor(&common.Backend{
		Type:     common.BackendType_WIREGUARD,
		Config:   `{"interface_name":"wgde2"}`,
		Additive: true,
	})

	if len(c.backends) != 1 {
		t.Fatalf("only the matching core should go, %d left", len(c.backends))
	}
	if keep.stopped {
		t.Fatal("an additive Start must not touch the other cores")
	}
	if !replace.stopped {
		t.Fatal("the core being replaced must be shut down")
	}
}

// fakeBackend records whether it was shut down; nothing else in these tests
// touches a core, so the rest of the interface is inert.
type fakeBackend struct{ stopped bool }

func (f *fakeBackend) Started() bool       { return !f.stopped }
func (f *fakeBackend) Version() string     { return "test" }
func (f *fakeBackend) Logs() <-chan string { return nil }
func (f *fakeBackend) Restart() error      { return nil }
func (f *fakeBackend) Shutdown()           { f.stopped = true }

func (f *fakeBackend) SyncUser(context.Context, *common.User) error                { return nil }
func (f *fakeBackend) SyncUsers(context.Context, []*common.User) error             { return nil }
func (f *fakeBackend) UpdateUsers(context.Context, []*common.User) error           { return nil }
func (f *fakeBackend) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }

func (f *fakeBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return nil, nil
}

func (f *fakeBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return nil, nil
}

func (f *fakeBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, nil
}

func (f *fakeBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return nil, nil
}

func (f *fakeBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return nil, nil
}
