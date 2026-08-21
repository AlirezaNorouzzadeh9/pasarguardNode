package xray

import (
	"testing"

	"github.com/pasarguard/node/common"
)

func TestLimiterTracksOnlyLimitedUsers(t *testing.T) {
	l := newIPLimiter()
	l.track(&common.User{Email: "alice", IpLimit: 2})
	l.track(&common.User{Email: "bob"})

	limited, _ := l.snapshot()
	if _, ok := limited["alice"]; !ok {
		t.Fatal("a user with a limit should be tracked")
	}
	if _, ok := limited["bob"]; ok {
		t.Fatal("a user with no limit should not be tracked")
	}
}

func TestLimiterForgetsWhenLimitIsLifted(t *testing.T) {
	l := newIPLimiter()
	l.track(&common.User{Email: "alice", IpLimit: 1})
	l.markSuppressed("alice", &common.User{Email: "alice", IpLimit: 1})

	// The panel clears the limit; the user must stop being held to it, and must
	// not be left suppressed.
	l.track(&common.User{Email: "alice", IpLimit: 0})

	limited, suppressed := l.snapshot()
	if len(limited) != 0 {
		t.Fatalf("expected no limited users, got %v", limited)
	}
	if len(suppressed) != 0 {
		t.Fatalf("clearing a limit must release the user, got %v", suppressed)
	}
}

func TestLimiterForgetDropsUserEntirely(t *testing.T) {
	l := newIPLimiter()
	l.track(&common.User{Email: "alice", IpLimit: 1})
	l.markSuppressed("alice", &common.User{Email: "alice", IpLimit: 1})
	l.forget("alice")

	limited, suppressed := l.snapshot()
	if len(limited) != 0 || len(suppressed) != 0 {
		t.Fatal("a forgotten user should be gone from both maps")
	}
}

func TestLimiterSnapshotIsACopy(t *testing.T) {
	l := newIPLimiter()
	l.track(&common.User{Email: "alice", IpLimit: 1})

	limited, _ := l.snapshot()
	delete(limited, "alice")

	again, _ := l.snapshot()
	if _, ok := again["alice"]; !ok {
		t.Fatal("mutating a snapshot must not affect the limiter")
	}
}

func TestLimiterRestoreClearsSuppression(t *testing.T) {
	l := newIPLimiter()
	user := &common.User{Email: "alice", IpLimit: 1}
	l.track(user)
	l.markSuppressed("alice", user)
	l.markRestored("alice")

	limited, suppressed := l.snapshot()
	if _, ok := suppressed["alice"]; ok {
		t.Fatal("a restored user should no longer be suppressed")
	}
	if _, ok := limited["alice"]; !ok {
		t.Fatal("restoring must not stop enforcing the limit")
	}
}
