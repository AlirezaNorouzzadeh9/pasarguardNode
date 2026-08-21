package openvpn

import (
	"testing"

	"github.com/pasarguard/node/common"
)

// A user may hold only so many sessions at once. The newest connection is the
// one refused: the sessions already running belong to someone who is using the
// service, and dropping one of them to admit a newcomer interrupts the wrong
// person.

func storeWith(limit uint32) *userStore {
	s := newUserStore("ovpn")
	s.replaceAll([]*common.User{{
		Email:    "101",
		Inbounds: []string{"ovpn"},
		IpLimit:  limit,
		Proxies:  &common.Proxy{Openvpn: &common.Openvpn{Serial: "AA"}},
	}})
	return s
}

func TestSessionsBeyondTheLimitAreRefused(t *testing.T) {
	s := storeWith(2)

	for _, cid := range []string{"1", "2"} {
		if ok, reason := s.tryConnect("101", "AA", cid); !ok {
			t.Fatalf("session %s should have been allowed, got %q", cid, reason)
		}
	}
	if ok, reason := s.tryConnect("101", "AA", "3"); ok {
		t.Fatal("a third session was allowed past a limit of two")
	} else if reason == "" {
		t.Error("refusal should say why")
	}
}

func TestARefusedSessionDoesNotDisturbTheOnesAlreadyRunning(t *testing.T) {
	s := storeWith(1)
	s.tryConnect("101", "AA", "1")
	s.tryConnect("101", "AA", "2") // refused

	s.mu.RLock()
	defer s.mu.RUnlock()
	live := s.sessions["101"]
	if len(live) != 1 {
		t.Fatalf("expected the original session to survive alone, got %d", len(live))
	}
	if _, ok := live["1"]; !ok {
		t.Error("the session that was already connected is the one that should remain")
	}
}

func TestReauthOfACountedSessionIsNotANewConnection(t *testing.T) {
	// openvpn re-authenticates a live client periodically; that must not be
	// mistaken for a second device and refused.
	s := storeWith(1)
	s.tryConnect("101", "AA", "1")
	if ok, reason := s.tryConnect("101", "AA", "1"); !ok {
		t.Fatalf("reauth of an existing session was refused: %q", reason)
	}
}

func TestFreedSlotIsUsableAgain(t *testing.T) {
	s := storeWith(1)
	s.tryConnect("101", "AA", "1")
	s.releaseSession("101", "1")
	if ok, reason := s.tryConnect("101", "AA", "2"); !ok {
		t.Fatalf("after a disconnect the user should be able to connect again: %q", reason)
	}
}

func TestNoLimitMeansNoLimit(t *testing.T) {
	s := storeWith(0)
	for _, cid := range []string{"1", "2", "3", "4", "5"} {
		if ok, _ := s.tryConnect("101", "AA", cid); !ok {
			t.Fatalf("session %s refused although the user has no limit", cid)
		}
	}
}
