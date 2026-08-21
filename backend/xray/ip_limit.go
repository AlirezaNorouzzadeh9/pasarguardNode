package xray

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
)

// Holding an xray user to a connection limit.
//
// xray can say where a user is connected from, but it cannot close a connection
// that is already open — RemoveUser only takes the account out of the inbound,
// and anything already authenticated keeps running until the client hangs up.
//
// That limitation is exactly the behaviour wanted here. Taking an over-limit
// user out of their inbounds leaves the connections they already had alone and
// refuses the next one, which is the same rule the other backends follow: the
// newest gives way. When they drop back under, the account goes back in.
//
// The suppression has to be re-applied rather than remembered by the panel: a
// sync from the panel carries the user's full entitlement and would put them
// straight back, so the loop simply removes them again on its next pass.

const (
	ipLimitInterval = 10 * time.Second
	ipLimitTimeout  = 8 * time.Second
)

type ipLimiter struct {
	mu sync.Mutex
	// Users currently taken out of their inbounds, with the entitlement needed
	// to put them back.
	suppressed map[string]*common.User
	// Every user the panel has told us about that carries a limit.
	limited map[string]*common.User
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{
		suppressed: make(map[string]*common.User),
		limited:    make(map[string]*common.User),
	}
}

// track records a user's limit, or forgets them when they no longer have one.
func (l *ipLimiter) track(u *common.User) {
	email := u.GetEmail()
	if email == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if u.GetIpLimit() == 0 {
		delete(l.limited, email)
		delete(l.suppressed, email)
		return
	}
	l.limited[email] = u
}

// forget drops a user entirely (they were removed from this backend).
func (l *ipLimiter) forget(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.limited, email)
	delete(l.suppressed, email)
}

func (l *ipLimiter) snapshot() (limited map[string]*common.User, suppressed map[string]*common.User) {
	l.mu.Lock()
	defer l.mu.Unlock()
	limited = make(map[string]*common.User, len(l.limited))
	for email, u := range l.limited {
		limited[email] = u
	}
	suppressed = make(map[string]*common.User, len(l.suppressed))
	for email, u := range l.suppressed {
		suppressed[email] = u
	}
	return limited, suppressed
}

func (l *ipLimiter) markSuppressed(email string, u *common.User) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suppressed[email] = u
}

func (l *ipLimiter) markRestored(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.suppressed, email)
}

// limitLoop keeps limited users inside their allowance.
func (x *Xray) limitLoop(ctx context.Context) {
	ticker := time.NewTicker(ipLimitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			x.enforceIPLimits(ctx)
		}
	}
}

// enforceIPLimits removes users who are connected from too many addresses, and
// puts back the ones who no longer are.
func (x *Xray) enforceIPLimits(ctx context.Context) {
	if x.ipLimits == nil || x.handler == nil {
		return
	}
	limited, suppressed := x.ipLimits.snapshot()

	for email, user := range limited {
		callCtx, cancel := context.WithTimeout(ctx, ipLimitTimeout)
		resp, err := x.handler.GetUserOnlineIpListStats(callCtx, email)
		cancel()
		if err != nil {
			continue
		}
		over := uint32(len(resp.GetIps())) > user.GetIpLimit()
		_, isSuppressed := suppressed[email]

		switch {
		case over && !isSuppressed:
			// Their open connections carry on; the next one is refused.
			blocked := &common.User{Email: email, Proxies: user.GetProxies()}
			if err := x.SyncUser(ctx, blocked); err == nil {
				x.ipLimits.markSuppressed(email, user)
				log.Printf("xray: %s is connected from %d addresses over a limit of %d; refusing new connections",
					email, len(resp.GetIps()), user.GetIpLimit())
			}
		case !over && isSuppressed:
			if err := x.SyncUser(ctx, user); err == nil {
				x.ipLimits.markRestored(email)
				log.Printf("xray: %s is back within their limit; accepting connections again", email)
			}
		case over && isSuppressed:
			// A panel sync will have handed them their inbounds back, so take
			// them out again rather than trusting the earlier removal to hold.
			blocked := &common.User{Email: email, Proxies: user.GetProxies()}
			_ = x.SyncUser(ctx, blocked)
		}
	}
}
