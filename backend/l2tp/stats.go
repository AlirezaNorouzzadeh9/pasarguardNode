package l2tp

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

func (o *L2TP) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(o.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.poll()
		}
	}
}

// poll attributes each live PPP session's interface counters to its user,
// accumulates traffic across session churn and refreshes the online snapshot.
// Sessions come from the pppd ip-up hook
// (interface -> username); byte counters from the interface statistics.
func (o *L2TP) poll() {
	// The session directory is shared by every L2TP core; only account for the
	// sessions this core owns (untagged files predate the tag and are kept).
	var sessions []l2tpSession
	for _, s := range readSessions() {
		if s.tag != "" && s.tag != o.config.InboundTag {
			continue
		}
		sessions = append(sessions, s)
	}
	perUser := make(map[string][]l2tpSession)
	present := make(map[string]struct{})
	for _, s := range sessions {
		perUser[s.user] = append(perUser[s.user], s)
		present[s.ifname] = struct{}{}
	}

	// Sessions that ended since the last tick, from the records the ip-down hook
	// leaves. Same per-core filter as live sessions.
	var finals []finalRecord
	for _, rec := range readFinalRecords() {
		if rec.tag != "" && rec.tag != o.config.InboundTag {
			continue
		}
		finals = append(finals, rec)
	}

	var samples []stats.Sample

	o.mu.Lock()
	growthRx := make(map[string]int64)
	growthTx := make(map[string]int64)

	// Ended sessions are settled BEFORE the live ones. Their closing counters
	// have to be measured against the baseline of the interface as THEY left it,
	// and ppp0 is handed to the next caller within seconds: settle afterwards and
	// the baseline would already belong to somebody else. Clearing the baseline
	// here is also what makes the reused interface correct — the kernel counters
	// restart at zero with it, so the next session is measured from zero too.
	for _, rec := range finals {
		last, seen := o.ifSeen[rec.ifname]
		dRx, dTx := rec.rx, rec.tx
		if seen {
			dRx, dTx = rec.rx-last[0], rec.tx-last[1]
		}
		// The hook falls back to pppd's link totals when the interface is already
		// gone, and those are counted a layer below /sys — close, but not
		// guaranteed to be greater. Bill nothing rather than the whole session.
		if dRx < 0 {
			dRx = 0
		}
		if dTx < 0 {
			dTx = 0
		}
		delete(o.ifSeen, rec.ifname)
		growthRx[rec.user] += dRx
		growthTx[rec.user] += dTx
		if _, live := perUser[rec.user]; !live {
			// Nothing of theirs is running any more, but this last piece still
			// has to reach the tracker below.
			perUser[rec.user] = nil
		}
		_ = os.Remove(rec.path)
	}

	for _, s := range sessions {
		rx, tx := ifaceBytes(s.ifname)
		last := o.ifSeen[s.ifname]
		dRx, dTx := rx-last[0], tx-last[1]
		if dRx < 0 {
			dRx = rx
		}
		if dTx < 0 {
			dTx = tx
		}
		o.ifSeen[s.ifname] = [2]int64{rx, tx}
		growthRx[s.user] += dRx
		growthTx[s.user] += dTx
	}
	// Forget interfaces with neither a live session nor a final record — pppd was
	// killed outright, so the hook never ran and the tail is unrecoverable. The
	// baseline still has to go, or a later session on the same name would be
	// measured against a stranger's counters.
	for ifn := range o.ifSeen {
		if _, ok := present[ifn]; !ok {
			delete(o.ifSeen, ifn)
		}
	}
	now := time.Now().Unix()
	onlineIPs := make(map[string]map[string]int64, len(perUser))
	for user, list := range perUser {
		o.cumRx[user] += growthRx[user]
		o.cumTx[user] += growthTx[user]
		o.totalRx += growthRx[user]
		o.totalTx += growthTx[user]
		ips := make(map[string]int64, len(list))
		endpoint := ""
		for _, s := range list {
			ip := s.clientIP
			if ip == "" {
				ip = s.tunnelIP
			}
			if ip != "" {
				ips[ip] = now
				if endpoint == "" {
					endpoint = ip
				}
			}
		}
		onlineIPs[user] = ips
		samples = append(samples, stats.Sample{
			PublicKey:  user,
			Email:      user,
			Rx:         o.cumRx[user],
			Tx:         o.cumTx[user],
			EndpointIP: endpoint,
		})
	}
	o.onlineIPs = onlineIPs
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}

	o.enforceSessionLimits(perUser)
}

// enforceSessionLimits hangs up the sessions a user is over their limit by.
//
// pppd authenticates against chap-secrets on its own, with no hook this process
// sits in, so a session cannot be refused as it is made — it can only be ended
// once seen, within one poll interval. The newest are the ones to go: the
// sessions already running belong to someone using the service, and ending one
// of those to make room for a newcomer interrupts the wrong person.
func (o *L2TP) enforceSessionLimits(perUser map[string][]l2tpSession) {
	if o.users == nil {
		return
	}
	for user, sessions := range perUser {
		limit := o.users.limitFor(user)
		if limit == 0 || len(sessions) <= int(limit) {
			continue
		}

		// Oldest first, so everything past the limit is the newest.
		ordered := make([]l2tpSession, len(sessions))
		copy(ordered, sessions)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].started < ordered[j].started })

		for _, session := range ordered[limit:] {
			if signalSession(session) {
				o.emitLogf("Info", "l2tp: %s is over their %d-session limit; ended the newest (%s)",
					user, limit, session.ifname)
			}
		}
	}
}

func (o *L2TP) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	switch request.GetType() {
	case common.StatType_UserStat:
		return o.statsTracker.GetStats(ctx, []string{request.GetName()}, request.GetReset_()), nil
	case common.StatType_UsersStat:
		return o.statsTracker.GetUsersStats(ctx, request.GetReset_()), nil
	case common.StatType_Outbound, common.StatType_Outbounds:
		o.mu.Lock()
		totalRx, totalTx := o.totalRx, o.totalTx
		o.mu.Unlock()
		dRx, dTx := o.interfaceStats.Delta(totalRx, totalTx, request.GetReset_())
		return &common.StatResponse{
			Stats: stats.BuildInterfaceStats(o.config.InboundTag, "outbound", dRx, dTx),
		}, nil
	default:
		return nil, errors.New("unsupported stat type for l2tp")
	}
}

func (o *L2TP) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	value := int64(0)
	if o.statsTracker.AnyActiveSince([]string{email}, time.Now().Add(-onlineActivityThreshold)) {
		value = 1
	}
	return &common.OnlineStatResponse{Name: email, Value: value}, nil
}

func (o *L2TP) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	response := &common.StatsOnlineIpListResponse{Name: email, Ips: make(map[string]int64)}
	o.mu.RLock()
	for ip, ts := range o.onlineIPs[email] {
		response.Ips[ip] = ts
	}
	o.mu.RUnlock()
	return response, nil
}

func (o *L2TP) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        m.NumGC,
		Alloc:        m.Alloc,
		TotalAlloc:   m.TotalAlloc,
		Sys:          m.Sys,
		Mallocs:      m.Mallocs,
		Frees:        m.Frees,
		LiveObjects:  m.Mallocs - m.Frees,
		PauseTotalNs: m.PauseTotalNs,
		Uptime:       uint32(time.Since(o.startTime).Seconds()),
	}, nil
}
