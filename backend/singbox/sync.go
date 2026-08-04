package singbox

import (
	"context"
	"fmt"

	"github.com/pasarguard/node/common"
)

// SyncUser folds one user into the current set and reapplies it.
//
// sing-box cannot add a single user to a running inbound, so this costs the
// same as a full sync: the affected inbounds are rebuilt. Callers that push
// users one at a time will therefore reconnect that protocol's clients each
// time — the panel's bulk paths (SyncUsers/UpdateUsers) are much cheaper.
func (s *SingBox) SyncUser(ctx context.Context, user *common.User) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	s.mu.Lock()
	replaced := false
	for i, u := range s.users {
		if u.GetEmail() == user.GetEmail() {
			s.users[i] = user
			replaced = true
			break
		}
	}
	if !replaced {
		s.users = append(s.users, user)
	}
	users := append([]*common.User(nil), s.users...)
	s.mu.Unlock()

	return s.rebuildUserInbounds(ctx, users)
}

// SyncUsers replaces the whole user set.
func (s *SingBox) SyncUsers(ctx context.Context, users []*common.User) error {
	s.mu.Lock()
	s.users = append([]*common.User(nil), users...)
	current := append([]*common.User(nil), s.users...)
	s.mu.Unlock()

	return s.rebuildUserInbounds(ctx, current)
}

// UpdateUsers merges the given users into the set (upsert by email).
func (s *SingBox) UpdateUsers(ctx context.Context, users []*common.User) error {
	s.mu.Lock()
	index := make(map[string]int, len(s.users))
	for i, u := range s.users {
		index[u.GetEmail()] = i
	}
	for _, u := range users {
		if u == nil {
			continue
		}
		if i, ok := index[u.GetEmail()]; ok {
			s.users[i] = u
		} else {
			index[u.GetEmail()] = len(s.users)
			s.users = append(s.users, u)
		}
	}
	current := append([]*common.User(nil), s.users...)
	s.mu.Unlock()

	return s.rebuildUserInbounds(ctx, current)
}

// UpdateUsersAndRestart applies the users and restarts, for changes that touch
// more than the user list.
func (s *SingBox) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	s.mu.Lock()
	s.users = append([]*common.User(nil), users...)
	s.mu.Unlock()
	return s.Restart()
}

// rebuildUserInbounds swaps every user-bearing inbound for one carrying the
// given users, leaving the rest of the instance — and every other protocol's
// live connections — untouched.
func (s *SingBox) rebuildUserInbounds(ctx context.Context, users []*common.User) error {
	s.mu.RLock()
	instance := s.instance
	running := s.state == lifecycleRunning
	s.mu.RUnlock()

	if !running || instance == nil {
		return errNotStarted
	}

	manager := instance.Inbound()
	router := instance.Router()
	logFactory := instance.LogFactory()

	var firstErr error
	for _, in := range s.config.Options.Inbounds {
		if !carriesUsers(in) {
			continue
		}
		applied, err := applyUsers(in, users)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n, _ := userCount(applied, users)

		// Remove-then-create is the only supported way to change users. The
		// window between the two is where that inbound's clients reconnect.
		if err := manager.Remove(in.Tag); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove inbound %q: %w", in.Tag, err)
			}
			continue
		}
		if err := manager.Create(
			ctx,
			router,
			logFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", applied.Type, applied.Tag)),
			applied.Tag,
			applied.Type,
			applied.Options,
		); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("recreate inbound %q: %w", in.Tag, err)
			}
			continue
		}
		s.emitLogf("singbox: inbound %q rebuilt with %d user(s)", applied.Tag, n)
	}
	return firstErr
}
