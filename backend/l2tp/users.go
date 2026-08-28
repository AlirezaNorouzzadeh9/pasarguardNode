package l2tp

import (
	"slices"
	"sync"

	"github.com/pasarguard/node/common"
)

// L2TP authenticates PPP clients with username/password (CHAP). Those live in
// the proxy table's ikev2 slot (GetIkev2) — the key predates the ikev2/l2tp
// drop and the panel's stored data still uses it. A user is an L2TP user when
// they carry those credentials and belong to this backend's inbound tag.

type userEntry struct {
	password string
	// Sessions this user may hold at once. Zero means no limit.
	ipLimit uint32
	// Per-direction throughput cap in kbit/s. Zero means unshaped.
	speedLimit uint32
}

// speedLimitFor returns the per-direction cap for a username (0 = unlimited).
func (s *userStore) speedLimitFor(username string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[username].speedLimit
}

type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
}

func newUserStore(inboundTag string) *userStore {
	return &userStore{inboundTag: inboundTag, users: make(map[string]userEntry)}
}

func credsFor(u *common.User) (username, password string, ok bool) {
	ik := u.GetProxies().GetIkev2()
	if ik == nil || ik.GetUsername() == "" || ik.GetPassword() == "" {
		return "", "", false
	}
	return ik.GetUsername(), ik.GetPassword(), true
}

func (s *userStore) wantsInterface(u *common.User) bool {
	if _, _, ok := credsFor(u); !ok {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

// replaceAll rebuilds the store from an authoritative user list. It returns the
// usernames no longer present (so their chap-secrets entries can be removed)
// and the ones whose password was rotated — a revoke: their live sessions
// authenticated with the old password and must not outlive it.
func (s *userStore) replaceAll(users []*common.User) (removed, rotated []string) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wantsInterface(u) {
			continue
		}
		username, password, _ := credsFor(u)
		next[username] = userEntry{password: password, ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
	}

	s.mu.Lock()
	for username, prev := range s.users {
		entry, ok := next[username]
		if !ok {
			removed = append(removed, username)
		} else if prev.password != entry.password {
			rotated = append(rotated, username)
		}
	}
	s.users = next
	s.mu.Unlock()
	return removed, rotated
}

// applyUser upserts one user. rotated is true when an existing user's password
// changed (a revoke): their live sessions were authenticated with the old
// password and must be torn down, exactly as openvpn kills on a changed serial.
// A limit change alone never counts — cutting a session because the operator
// adjusted a cap would disconnect the wrong person for the wrong reason.
func (s *userStore) applyUser(u *common.User) (username string, rotated bool, removed bool) {
	if !s.wantsInterface(u) {
		username = u.GetEmail()
		if username == "" {
			return "", false, false
		}
		s.mu.Lock()
		_, existed := s.users[username]
		delete(s.users, username)
		s.mu.Unlock()
		return username, false, existed
	}
	username, password, _ := credsFor(u)
	entry := userEntry{password: password, ipLimit: u.GetIpLimit(), speedLimit: u.GetSpeedLimit()}
	s.mu.Lock()
	prev, existed := s.users[username]
	s.users[username] = entry
	s.mu.Unlock()
	return username, existed && prev.password != entry.password, false
}

func (s *userStore) snapshot() map[string]userEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]userEntry, len(s.users))
	for k, v := range s.users {
		out[k] = v
	}
	return out
}

// limitFor returns how many sessions a user may hold at once, 0 meaning no limit.
func (s *userStore) limitFor(username string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[username].ipLimit
}
