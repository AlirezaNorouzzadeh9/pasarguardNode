package singbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// sing-box reports the authenticated user and source address of every live
// connection, and can close one by id — so unlike xray it can both count and
// act. These pin what gets closed: the newest addresses, grouped by address
// rather than by connection, since one client opens many at once.

type fakeClash struct {
	mu     sync.Mutex
	conns  []clashConnection
	closed []string
}

func (f *fakeClash) serve(t *testing.T) *clashClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{"connections": f.conns})
		case r.Method == http.MethodDelete:
			f.closed = append(f.closed, r.URL.Path[len("/connections/"):])
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return newClashClient(srv.URL, "")
}

func conn(id, user, ip, start string) clashConnection {
	c := clashConnection{ID: id, Start: start}
	c.Metadata.User = user
	c.Metadata.SrcIP = ip
	return c
}

func sbWith(t *testing.T, limit uint32, conns []clashConnection) (*SingBox, *fakeClash) {
	t.Helper()
	fake := &fakeClash{conns: conns}
	s := &SingBox{
		users:   map[string]userCredentials{"101": {hysteria2: "pw", ipLimit: limit}},
		logChan: make(chan string, 16),
	}
	s.client = fake.serve(t)
	return s, fake
}

func TestOnlineIpListReportsEveryAddressTheUserIsOn(t *testing.T) {
	s, _ := sbWith(t, 0, []clashConnection{
		conn("1", "101", "1.1.1.1", "a"),
		conn("2", "101", "1.1.1.1", "b"), // same address, one client
		conn("3", "101", "2.2.2.2", "c"),
		conn("4", "999", "3.3.3.3", "d"), // somebody else
	})

	resp, err := s.GetUserOnlineIpListStats(t.Context(), "101")
	if err != nil {
		t.Fatalf("GetUserOnlineIpListStats: %v", err)
	}
	if len(resp.Ips) != 2 {
		t.Fatalf("expected the two distinct addresses, got %v", resp.Ips)
	}
	if _, ok := resp.Ips["3.3.3.3"]; ok {
		t.Error("another user's address was reported")
	}
}

func TestConnectionsBeyondTheLimitAreClosedNewestFirst(t *testing.T) {
	s, fake := sbWith(t, 2, []clashConnection{
		conn("1", "101", "1.1.1.1", "2026-01-01T00:00:00Z"),
		conn("2", "101", "2.2.2.2", "2026-01-01T00:00:10Z"),
		conn("3", "101", "3.3.3.3", "2026-01-01T00:00:20Z"), // newest
		conn("4", "101", "3.3.3.3", "2026-01-01T00:00:21Z"),
	})

	s.enforceIPLimits(t.Context())

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.closed) != 2 {
		t.Fatalf("expected both connections from the newest address to close, got %v", fake.closed)
	}
	for _, id := range fake.closed {
		if id == "1" || id == "2" {
			t.Errorf("closed connection %s, which was within the limit", id)
		}
	}
}

func TestManyConnectionsFromOneAddressCountOnce(t *testing.T) {
	// A browser alone opens dozens; counting connections rather than addresses
	// would cut off a single legitimate device instantly.
	s, fake := sbWith(t, 1, []clashConnection{
		conn("1", "101", "1.1.1.1", "a"),
		conn("2", "101", "1.1.1.1", "b"),
		conn("3", "101", "1.1.1.1", "c"),
	})

	s.enforceIPLimits(t.Context())

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.closed) != 0 {
		t.Fatalf("one address at a limit of one had connections closed: %v", fake.closed)
	}
}

func TestNoLimitClosesNothing(t *testing.T) {
	s, fake := sbWith(t, 0, []clashConnection{
		conn("1", "101", "1.1.1.1", "a"),
		conn("2", "101", "2.2.2.2", "b"),
		conn("3", "101", "3.3.3.3", "c"),
	})

	s.enforceIPLimits(t.Context())

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.closed) != 0 {
		t.Fatalf("connections closed although the user has no limit: %v", fake.closed)
	}
}

func TestAFreedSlotPlaceholderIsNobody(t *testing.T) {
	// Traffic can land on a slot whose credentials were just withdrawn; it
	// belongs to no user and must not be counted against one.
	s, _ := sbWith(t, 0, []clashConnection{conn("1", freeSlotName, "9.9.9.9", "a")})
	if got := s.userOf(conn("1", freeSlotName, "9.9.9.9", "a")); got != "" {
		t.Fatalf("placeholder resolved to user %q", got)
	}
}
