package l2tp

import (
	"os"
	"path/filepath"
	"testing"
)

// A live session whose user carries a limit is shaped on its tunnel address; a
// user with no limit is left alone even while connected.
func TestShapedClientsListsOnlyLimitedLiveSessions(t *testing.T) {
	sessionStateDir = t.TempDir()
	sessionFinalDir = t.TempDir()

	users := newUserStore("l2tp-test")
	users.users = map[string]userEntry{
		"173": {password: "x", speedLimit: 4000},
		"174": {password: "y"},
	}
	o := &L2TP{config: &Config{InboundTag: "l2tp-test"}, users: users}

	write := func(ifname, user, tunnelIP string) {
		body := "user=" + user + "\ntunnel_ip=" + tunnelIP + "\ntag=l2tp-test\npid=0\nstarted=1\n"
		if err := os.WriteFile(filepath.Join(sessionStateDir, ifname), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ppp0", "173", "10.77.0.9")
	write("ppp1", "174", "10.77.0.10")

	previous := sessionIsAlive
	sessionIsAlive = func(l2tpSession) bool { return true }
	t.Cleanup(func() { sessionIsAlive = previous })

	clients := o.ShapedClients()
	if len(clients) != 1 {
		t.Fatalf("only the limited user's session should be shaped, got %d", len(clients))
	}
	c := clients[0]
	if c.User != "173" || c.Address != "10.77.0.9" || c.LimitKbps != 4000 {
		t.Fatalf("unexpected shaped client: %+v", c)
	}
}
