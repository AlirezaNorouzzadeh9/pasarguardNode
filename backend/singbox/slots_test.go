package singbox

import (
	"context"
	"testing"

	"github.com/pasarguard/node/common"
)

// sing-box identifies a connected client by its index in the last list it was
// given, and a live session keeps the index it authenticated with. So a user's
// position is their identity while they stay connected, and these tests pin the
// one property that follows: it must not move underneath them.
//
// The bug this replaces was found in production behaviour, not in a test — a
// user connected and their traffic was billed to somebody else, because the
// list was rebuilt from a Go map and came out in a different order every push.

func indexOf(payload []clashUser, email string) int {
	for i, u := range payload {
		if u.Name == email {
			return i
		}
	}
	return -1
}

func newSB(users map[string]string) *SingBox {
	return &SingBox{users: users}
}

func TestSlotsSurviveRepeatedPushes(t *testing.T) {
	s := newSB(map[string]string{"101": "a", "102": "b", "103": "c", "104": "d"})

	first := s.buildPayloadLocked()
	want := map[string]int{}
	for _, e := range []string{"101", "102", "103", "104"} {
		want[e] = indexOf(first, e)
	}

	// Nothing changed; ten more pushes must produce the same layout. Map
	// iteration order differs between runs, so this is what caught the bug.
	for i := 0; i < 10; i++ {
		got := s.buildPayloadLocked()
		for email, idx := range want {
			if indexOf(got, email) != idx {
				t.Fatalf("push %d moved %s from %d to %d", i, email, idx, indexOf(got, email))
			}
		}
	}
}

func TestRemovedUserDoesNotShiftTheOthers(t *testing.T) {
	users := map[string]string{"101": "a", "102": "b", "103": "c"}
	s := newSB(users)
	before := s.buildPayloadLocked()
	keep := indexOf(before, "103")

	delete(users, "101") // the user in front of them leaves
	after := s.buildPayloadLocked()

	if got := indexOf(after, "103"); got != keep {
		t.Fatalf("103 moved from %d to %d when 101 was removed", keep, got)
	}
	if indexOf(after, "101") != -1 {
		t.Fatal("removed user is still present in the payload")
	}
}

func TestFreedSlotIsHeldButNotUsable(t *testing.T) {
	users := map[string]string{"101": "secret-a", "102": "secret-b"}
	s := newSB(users)
	first := s.buildPayloadLocked()
	gone := indexOf(first, "101")

	delete(users, "101")
	after := s.buildPayloadLocked()

	if after[gone].Name == "101" || after[gone].Password == "secret-a" {
		t.Fatal("a departed user's credential is still live in their old slot")
	}
	if after[gone].Name != freeSlotName {
		t.Fatalf("placeholder should be unresolvable, got name %q", after[gone].Name)
	}
	if after[gone].Password == "" {
		t.Fatal("placeholder must not have an empty password — that is a credential")
	}
}

func TestNewUserTakesAFreedSlotAndNotSomebodyElses(t *testing.T) {
	users := map[string]string{"101": "a", "102": "b", "103": "c"}
	s := newSB(users)
	first := s.buildPayloadLocked()
	freed := indexOf(first, "102")
	keptIndex := indexOf(first, "103")

	delete(users, "102")
	users["999"] = "z"
	after := s.buildPayloadLocked()

	if got := indexOf(after, "999"); got != freed {
		t.Fatalf("new user took slot %d, expected the freed %d", got, freed)
	}
	if got := indexOf(after, "103"); got != keptIndex {
		t.Fatalf("existing user 103 moved from %d to %d", keptIndex, got)
	}
}

func TestTrailingHolesAreTrimmed(t *testing.T) {
	users := map[string]string{"101": "a", "102": "b", "103": "c"}
	s := newSB(users)
	s.buildPayloadLocked()

	delete(users, "101")
	delete(users, "102")
	delete(users, "103")
	if got := len(s.buildPayloadLocked()); got != 0 {
		t.Fatalf("payload should be empty once every user is gone, got %d entries", got)
	}
}

func TestPlaceholderPasswordsDifferPerSlot(t *testing.T) {
	// Identical placeholders across slots would be one shared password; a fixed
	// one across nodes would be worse still.
	if freeSlotPassword(0) == freeSlotPassword(1) {
		t.Fatal("two free slots share a password")
	}
	if slotNonce == "" {
		t.Fatal("slot nonce is empty, making placeholder passwords predictable")
	}
}

// A user who is out of data or expired keeps their credential — the panel stops
// listing the inbounds they may use rather than erasing it. Judging membership
// by the credential alone left them fully served, free to open new connections
// long after their quota was gone.

func sbWithTags(tags ...string) *SingBox {
	return &SingBox{config: &Config{inboundTags: tags}, users: map[string]string{}}
}

func user(email, auth string, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: auth}},
	}
}

func TestUserWithNoInboundsIsNotServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	if _, _, ok := s.hysteriaCredential(user("974", "secret")); ok {
		t.Fatal("a user entitled to no inbound is still being served")
	}
}

func TestUserEntitledToThisInboundIsServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	email, auth, ok := s.hysteriaCredential(user("974", "secret", "singbox-hy2"))
	if !ok || email != "974" || auth != "secret" {
		t.Fatalf("active user rejected: %q %q %v", email, auth, ok)
	}
}

func TestUserEntitledOnlyElsewhereIsNotServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	if _, _, ok := s.hysteriaCredential(user("974", "secret", "some-xray-inbound")); ok {
		t.Fatal("a user with no inbound on this core is being served by it")
	}
}

func TestLimitedUserIsDroppedOnSync(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	s.pushStop = make(chan struct{})
	_ = s.SyncUser(context.Background(), user("974", "secret", "singbox-hy2"))
	if _, present := s.users["974"]; !present {
		t.Fatal("active user was not added")
	}
	// Same user, now limited: same credential, no inbounds.
	_ = s.SyncUser(context.Background(), user("974", "secret"))
	if _, present := s.users["974"]; present {
		t.Fatal("limited user is still in the pushed set")
	}
}
