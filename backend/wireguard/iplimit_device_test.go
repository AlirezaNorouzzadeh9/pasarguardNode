package wireguard

import (
	"testing"
	"time"
)

// Clients that reach the node through a relay all arrive from the relay's
// address, so the limit has to count endpoints including the source port. The
// risk that buys is mistaking one device that re-bound its NAT port for two, so
// only endpoints seen recently count.
func TestCountRecent(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name   string
		window map[string]time.Time
		want   int
	}{
		{"nothing seen", map[string]time.Time{}, 0},
		{
			"one device",
			map[string]time.Time{"1.2.3.4:1111": now},
			1,
		},
		{
			"two devices behind one relay address both stay fresh",
			map[string]time.Time{
				"20.20.20.1:1111": now.Add(-5 * time.Second),
				"20.20.20.1:2222": now.Add(-8 * time.Second),
			},
			2,
		},
		{
			"a port the device abandoned goes stale and stops counting",
			map[string]time.Time{
				"20.20.20.1:1111": now.Add(-wgDeviceRecency - time.Second),
				"20.20.20.1:2222": now,
			},
			1,
		},
		{
			"an endpoint right on the recency edge still counts",
			map[string]time.Time{"20.20.20.1:1111": now.Add(-wgDeviceRecency)},
			1,
		},
		{
			"everything stale counts as nobody connected",
			map[string]time.Time{
				"20.20.20.1:1111": now.Add(-2 * wgDeviceRecency),
				"20.20.20.1:2222": now.Add(-3 * wgDeviceRecency),
			},
			0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countRecent(tc.window, now); got != tc.want {
				t.Fatalf("countRecent() = %d, want %d", got, tc.want)
			}
		})
	}
}

// The recency has to be long enough for two devices that alternate to both be
// seen (WireGuard keeps one endpoint per peer, so they overwrite each other),
// and short enough that an abandoned port drops out before the strike count
// would kick the user.
func TestDeviceRecencySpansSeveralPolls(t *testing.T) {
	const poll = 10 * time.Second // STATS_UPDATE_INTERVAL_SECONDS default
	if wgDeviceRecency < 3*poll {
		t.Fatalf("recency %v is under three poll intervals; alternating devices would be missed", wgDeviceRecency)
	}
	if wgDeviceRecency >= wgIPWindow {
		t.Fatalf("recency %v must be shorter than the retention window %v", wgDeviceRecency, wgIPWindow)
	}
}
