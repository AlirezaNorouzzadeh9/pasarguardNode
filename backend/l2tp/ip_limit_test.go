package l2tp

import (
	"testing"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

// pppd authenticates on its own, so an over-limit session cannot be refused as
// it is made — only ended once the poll loop sees it. These pin which ones go:
// the newest, because the sessions already running belong to someone using the
// service.

func limitedL2TP(t *testing.T, limit uint32) *L2TP {
	t.Helper()
	o := &L2TP{
		config:       &Config{InboundTag: "l2tp-test"},
		statsTracker: stats.New(),
		users:        newUserStore("l2tp-test"),
		ifSeen:       map[string][2]int64{},
		cumRx:        map[string]int64{},
		cumTx:        map[string]int64{},
		onlineIPs:    map[string]map[string]int64{},
	}
	o.users.replaceAll([]*common.User{{
		Email:    "173",
		Inbounds: []string{"l2tp-test"},
		IpLimit:  limit,
		Proxies:  &common.Proxy{Ikev2: &common.Ikev2{Username: "173", Password: "pw"}},
	}})
	return o
}

// killed records what enforcement would have signalled, without needing a pppd.
func recordKills(t *testing.T) *[]string {
	t.Helper()
	var killed []string
	previous := signalSession
	signalSession = func(s l2tpSession) bool {
		killed = append(killed, s.ifname)
		return true
	}
	t.Cleanup(func() { signalSession = previous })
	return &killed
}

func sess(user, ifname string, started int64) l2tpSession {
	return l2tpSession{user: user, ifname: ifname, tag: "l2tp-test", pid: 1234, started: started}
}

func TestSessionsOverTheLimitAreEndedNewestFirst(t *testing.T) {
	o := limitedL2TP(t, 2)
	killed := recordKills(t)

	o.enforceSessionLimits(map[string][]l2tpSession{
		"173": {sess("173", "ppp2", 300), sess("173", "ppp0", 100), sess("173", "ppp1", 200)},
	})

	if len(*killed) != 1 || (*killed)[0] != "ppp2" {
		t.Fatalf("expected only the newest session (ppp2) to be ended, got %v", *killed)
	}
}

func TestSessionsWithinTheLimitAreLeftAlone(t *testing.T) {
	o := limitedL2TP(t, 2)
	killed := recordKills(t)

	o.enforceSessionLimits(map[string][]l2tpSession{
		"173": {sess("173", "ppp0", 100), sess("173", "ppp1", 200)},
	})

	if len(*killed) != 0 {
		t.Fatalf("a user at their limit had sessions ended: %v", *killed)
	}
}

func TestNoLimitEndsNothing(t *testing.T) {
	o := limitedL2TP(t, 0)
	killed := recordKills(t)

	o.enforceSessionLimits(map[string][]l2tpSession{
		"173": {sess("173", "ppp0", 1), sess("173", "ppp1", 2), sess("173", "ppp2", 3), sess("173", "ppp3", 4)},
	})

	if len(*killed) != 0 {
		t.Fatalf("sessions ended although the user has no limit: %v", *killed)
	}
}

func TestEveryoneOverTheLimitLosesTheExtras(t *testing.T) {
	o := limitedL2TP(t, 1)
	killed := recordKills(t)

	o.enforceSessionLimits(map[string][]l2tpSession{
		"173": {sess("173", "ppp0", 100), sess("173", "ppp1", 200), sess("173", "ppp2", 300)},
	})

	if len(*killed) != 2 {
		t.Fatalf("expected the two newest to be ended, got %v", *killed)
	}
	for _, name := range *killed {
		if name == "ppp0" {
			t.Error("the oldest session was ended; it is the one that should survive")
		}
	}
}
