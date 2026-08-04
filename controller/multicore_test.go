package controller

import (
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
