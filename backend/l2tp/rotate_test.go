package l2tp

import (
	"testing"

	"github.com/pasarguard/node/common"
)

func l2tpUser(id, password string, speed uint32) *common.User {
	return &common.User{
		Email:      id,
		Inbounds:   []string{"l2tp-test"},
		SpeedLimit: speed,
		Proxies: &common.Proxy{
			Ikev2: &common.Ikev2{Username: id, Password: password},
		},
	}
}

// A password rotation is a revoke: the store must say so, so the live session
// that authenticated with the old password gets torn down.
func TestApplyUserReportsPasswordRotation(t *testing.T) {
	s := newUserStore("l2tp-test")

	if _, rotated, _ := s.applyUser(l2tpUser("3", "old", 0)); rotated {
		t.Fatal("a first sighting is not a rotation")
	}
	if _, rotated, _ := s.applyUser(l2tpUser("3", "new", 0)); !rotated {
		t.Fatal("a changed password must be reported as rotated")
	}
}

// Changing only a limit must never cut the session: the operator adjusted a
// cap, nobody revoked anything.
func TestApplyUserLimitChangeIsNotARotation(t *testing.T) {
	s := newUserStore("l2tp-test")
	s.applyUser(l2tpUser("3", "pw", 1000))

	if _, rotated, _ := s.applyUser(l2tpUser("3", "pw", 9000)); rotated {
		t.Fatal("a speed-limit change alone must not tear the session down")
	}
}

func TestReplaceAllReportsRotationsAndRemovals(t *testing.T) {
	s := newUserStore("l2tp-test")
	s.applyUser(l2tpUser("3", "old", 0))
	s.applyUser(l2tpUser("4", "keep", 0))
	s.applyUser(l2tpUser("5", "gone", 0))

	removed, rotated := s.replaceAll([]*common.User{
		l2tpUser("3", "new", 0),
		l2tpUser("4", "keep", 500),
	})

	if len(removed) != 1 || removed[0] != "5" {
		t.Fatalf("removed = %v, want [5]", removed)
	}
	if len(rotated) != 1 || rotated[0] != "3" {
		t.Fatalf("rotated = %v, want [3]", rotated)
	}
}
