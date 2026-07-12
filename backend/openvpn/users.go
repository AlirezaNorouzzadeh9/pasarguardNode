package openvpn

import (
	"slices"
	"sync"

	"github.com/pasarguard/node/common"
)

// userEntry is the authorization record for one user (keyed by common name = user id).
type userEntry struct {
	serial      string
	fingerprint string
}

// userStore is the authorized-user allowlist consulted by the management client.
// Membership is positive: a common name absent from the map is denied.
type userStore struct {
	inboundTag string
	mu         sync.RWMutex
	users      map[string]userEntry
}

func newUserStore(inboundTag string) *userStore {
	return &userStore{inboundTag: inboundTag, users: make(map[string]userEntry)}
}

// authorize implements authDecider: the CN must be present and, when a serial
// is pinned, must match the connecting certificate's serial.
func (s *userStore) authorize(commonName, serial string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.users[commonName]
	if !ok {
		return false
	}
	if entry.serial != "" && entry.serial != serial {
		return false
	}
	return true
}

// wantsInterface reports whether a synced user belongs to this backend's inbound.
func (s *userStore) wantsInterface(u *common.User) bool {
	if u.GetProxies().GetOpenvpn() == nil {
		return false
	}
	return slices.Contains(u.GetInbounds(), s.inboundTag)
}

// upsert adds or updates a user. Returns (changedSerial, removed) so the caller
// can decide whether to kill an existing session.
func (s *userStore) applyUser(u *common.User) (cn string, changedSerial bool, removed bool) {
	cn = u.GetEmail()
	if cn == "" {
		return "", false, false
	}

	if !s.wantsInterface(u) {
		s.mu.Lock()
		_, existed := s.users[cn]
		delete(s.users, cn)
		s.mu.Unlock()
		return cn, false, existed
	}

	ov := u.GetProxies().GetOpenvpn()
	entry := userEntry{serial: ov.GetSerial(), fingerprint: ov.GetFingerprint()}

	s.mu.Lock()
	prev, existed := s.users[cn]
	s.users[cn] = entry
	s.mu.Unlock()

	return cn, existed && prev.serial != entry.serial, false
}

// replaceAll rebuilds the store from an authoritative user list and returns the
// set of common names that are no longer present (so their sessions can be killed).
func (s *userStore) replaceAll(users []*common.User) (removed []string) {
	next := make(map[string]userEntry)
	for _, u := range users {
		if !s.wantsInterface(u) {
			continue
		}
		cn := u.GetEmail()
		if cn == "" {
			continue
		}
		ov := u.GetProxies().GetOpenvpn()
		next[cn] = userEntry{serial: ov.GetSerial(), fingerprint: ov.GetFingerprint()}
	}

	s.mu.Lock()
	for cn := range s.users {
		if _, ok := next[cn]; !ok {
			removed = append(removed, cn)
		}
	}
	s.users = next
	s.mu.Unlock()
	return removed
}

func (s *userStore) commonNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.users))
	for cn := range s.users {
		names = append(names, cn)
	}
	return names
}

func (s *userStore) has(commonName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[commonName]
	return ok
}
