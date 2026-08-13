package singbox

import (
	"context"
	"strings"
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

// hy builds a user who has only a hysteria2 secret, which is what this backend
// understood before it learned the other protocols.
func hy(auth string) userCredentials { return userCredentials{hysteria2: auth} }

func newSB(users map[string]userCredentials) *SingBox {
	return &SingBox{users: users}
}

// payload renders the current slots the way a hysteria2 inbound would see them.
func (s *SingBox) payload() []clashUser {
	s.reconcileSlotsLocked()
	return s.payloadForLocked(credHysteria2)
}

func TestSlotsSurviveRepeatedPushes(t *testing.T) {
	s := newSB(map[string]userCredentials{
		"101": hy("a"), "102": hy("b"), "103": hy("c"), "104": hy("d"),
	})

	first := s.payload()
	want := map[string]int{}
	for _, e := range []string{"101", "102", "103", "104"} {
		want[e] = indexOf(first, e)
	}

	// Nothing changed; ten more pushes must produce the same layout. Map
	// iteration order differs between runs, so this is what caught the bug.
	for i := 0; i < 10; i++ {
		got := s.payload()
		for email, idx := range want {
			if indexOf(got, email) != idx {
				t.Fatalf("push %d moved %s from %d to %d", i, email, idx, indexOf(got, email))
			}
		}
	}
}

func TestRemovedUserDoesNotShiftTheOthers(t *testing.T) {
	users := map[string]userCredentials{"101": hy("a"), "102": hy("b"), "103": hy("c")}
	s := newSB(users)
	before := s.payload()
	keep := indexOf(before, "103")

	delete(users, "101") // the user in front of them leaves
	after := s.payload()

	if got := indexOf(after, "103"); got != keep {
		t.Fatalf("103 moved from %d to %d when 101 was removed", keep, got)
	}
	if indexOf(after, "101") != -1 {
		t.Fatal("removed user is still present in the payload")
	}
}

func TestFreedSlotIsHeldButNotUsable(t *testing.T) {
	users := map[string]userCredentials{"101": hy("secret-a"), "102": hy("secret-b")}
	s := newSB(users)
	first := s.payload()
	gone := indexOf(first, "101")

	delete(users, "101")
	after := s.payload()

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
	users := map[string]userCredentials{"101": hy("a"), "102": hy("b"), "103": hy("c")}
	s := newSB(users)
	first := s.payload()
	freed := indexOf(first, "102")
	keptIndex := indexOf(first, "103")

	delete(users, "102")
	users["999"] = hy("z")
	after := s.payload()

	if got := indexOf(after, "999"); got != freed {
		t.Fatalf("new user took slot %d, expected the freed %d", got, freed)
	}
	if got := indexOf(after, "103"); got != keptIndex {
		t.Fatalf("existing user 103 moved from %d to %d", keptIndex, got)
	}
}

func TestTrailingHolesAreTrimmed(t *testing.T) {
	users := map[string]userCredentials{"101": hy("a"), "102": hy("b"), "103": hy("c")}
	s := newSB(users)
	s.payload()

	delete(users, "101")
	delete(users, "102")
	delete(users, "103")
	if got := len(s.payload()); got != 0 {
		t.Fatalf("payload should be empty once every user is gone, got %d entries", got)
	}
}

func TestPlaceholderSecretsDifferPerSlot(t *testing.T) {
	// Identical placeholders across slots would be one shared password; a fixed
	// one across nodes would be worse still.
	if freeSlotSecret(credHysteria2, 0) == freeSlotSecret(credHysteria2, 1) {
		t.Fatal("two free slots share a password")
	}
	if slotNonce == "" {
		t.Fatal("slot nonce is empty, making placeholder passwords predictable")
	}
}

// ------------------------------------------------- one secret is not the others

// The backend knew only hysteria2, so it sent that one secret to every inbound
// and left every other protocol's tag out of its list entirely. A vless inbound
// therefore never received a user, and the one time a password did reach one it
// was accepted rather than refused — sing-box stores the zero uuid instead.

func TestVlessInboundIsSentAUUIDAndNotAPassword(t *testing.T) {
	s := newSB(map[string]userCredentials{
		"101": {hysteria2: "hy-secret", vlessUUID: "7599e7ed-7dca-46cb-a2ee-1a61bfdabbe7"},
	})
	s.reconcileSlotsLocked()

	got := s.payloadForLocked(credVLESS)[0]
	if got.UUID != "7599e7ed-7dca-46cb-a2ee-1a61bfdabbe7" {
		t.Fatalf("vless user was not sent their uuid, got %q", got.UUID)
	}
	if got.Password != "" {
		t.Fatalf("vless user carries a password field: %q", got.Password)
	}

	hys := s.payloadForLocked(credHysteria2)[0]
	if hys.Password != "hy-secret" || hys.UUID != "" {
		t.Fatalf("hysteria2 user got the wrong shape: %+v", hys)
	}
}

func TestAUserKeepsOnePositionAcrossProtocols(t *testing.T) {
	// The lists are separate but the positions are not: a session authenticated
	// at index 2 on one inbound must mean the same person on every other.
	s := newSB(map[string]userCredentials{
		"101": {hysteria2: "a", vlessUUID: "11111111-1111-4111-8111-111111111111"},
		"102": {hysteria2: "b"},
		"103": {vlessUUID: "22222222-2222-4222-8222-222222222222"},
	})
	s.reconcileSlotsLocked()

	hys := s.payloadForLocked(credHysteria2)
	vls := s.payloadForLocked(credVLESS)
	if len(hys) != len(vls) {
		t.Fatalf("lists differ in length: %d vs %d", len(hys), len(vls))
	}
	for _, email := range []string{"101", "102", "103"} {
		if a, b := indexOf(hys, email), indexOf(vls, email); a != -1 && b != -1 && a != b {
			t.Fatalf("%s sits at %d on hysteria2 and %d on vless", email, a, b)
		}
	}
}

func TestAUserMissingThisProtocolHoldsTheirSlotUnusably(t *testing.T) {
	// Dropping them instead would shift everyone below, which is the exact bug
	// the slot table exists to prevent.
	s := newSB(map[string]userCredentials{
		"101": {hysteria2: "a"}, // no vless secret
		"102": {hysteria2: "b", vlessUUID: "33333333-3333-4333-8333-333333333333"},
	})
	s.reconcileSlotsLocked()

	hys := s.payloadForLocked(credHysteria2)
	vls := s.payloadForLocked(credVLESS)
	at := indexOf(hys, "101")
	if vls[at].Name == "101" {
		t.Fatal("a user with no vless secret was still named on the vless inbound")
	}
	if vls[at].Name != freeSlotName {
		t.Fatalf("expected a placeholder at %d, got %q", at, vls[at].Name)
	}
	if indexOf(vls, "102") != indexOf(hys, "102") {
		t.Fatal("the other user moved because of the gap")
	}
}

func TestUUIDPlaceholdersAreRealAndDistinctUUIDs(t *testing.T) {
	// A placeholder that is not a uuid is not refused — sing-box stores the zero
	// uuid — so every such slot would share one well-known live credential.
	a, b := freeSlotSecret(credVLESS, 0), freeSlotSecret(credVLESS, 1)
	for _, got := range []string{a, b} {
		if len(got) != 36 || strings.Count(got, "-") != 4 {
			t.Fatalf("placeholder is not uuid-shaped: %q", got)
		}
		if got == "00000000-0000-0000-0000-000000000000" {
			t.Fatal("placeholder is the zero uuid, which authenticates")
		}
	}
	if a == b {
		t.Fatal("two free slots share a uuid")
	}
}

// ---------------------------------------------------------------- entitlement

// A user who is out of data or expired keeps their credential — the panel stops
// listing the inbounds they may use rather than erasing it. Judging membership
// by the credential alone left them fully served, free to open new connections
// long after their quota was gone.

func sbWithTags(tags ...string) *SingBox {
	inbounds := make([]managedInbound, len(tags))
	for i, tag := range tags {
		inbounds[i] = managedInbound{tag: tag, kind: credHysteria2}
	}
	return &SingBox{config: &Config{inbounds: inbounds}, users: map[string]userCredentials{}}
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
	if _, _, ok := s.credentials(user("974", "secret")); ok {
		t.Fatal("a user entitled to no inbound is still being served")
	}
}

func TestUserEntitledToThisInboundIsServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	email, creds, ok := s.credentials(user("974", "secret", "singbox-hy2"))
	if !ok || email != "974" || creds.hysteria2 != "secret" {
		t.Fatalf("active user rejected: %q %+v %v", email, creds, ok)
	}
}

func TestUserEntitledOnlyElsewhereIsNotServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	if _, _, ok := s.credentials(user("974", "secret", "some-xray-inbound")); ok {
		t.Fatal("a user with no inbound on this core is being served by it")
	}
}

func TestUserWithNoSecretAtAllIsNotServed(t *testing.T) {
	s := sbWithTags("singbox-hy2")
	entitled := &common.User{Email: "974", Inbounds: []string{"singbox-hy2"}, Proxies: &common.Proxy{}}
	if _, _, ok := s.credentials(entitled); ok {
		t.Fatal("a user with no credential of any kind is being served")
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
