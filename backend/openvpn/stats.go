package openvpn

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

// statsLoop polls the management interface and feeds per-user byte deltas into
// the shared stats tracker (same delta/reset engine the wireguard backend uses).
func (o *OpenVPN) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(o.updateInterval)
	defer ticker.Stop()

	cleanup := time.NewTicker(5 * time.Minute)
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.collectStats()
		case <-cleanup.C:
			o.statsTracker.CleanupDeletedEntries()
		}
	}
}

// endedSession is a session's final byte totals, reported by the management
// interface as the client disconnects.
type endedSession struct {
	clientID   string
	commonName string
	rx         int64
	tx         int64
}

// recordSessionEnd queues a finished session's totals for the next poll.
//
// Called from the management reader goroutine; the poll loop applies it. See
// endedSessions on the struct for why this is queued rather than applied here.
func (o *OpenVPN) recordSessionEnd(cid, commonName string, rx, tx int64) {
	if cid == "" || commonName == "" {
		return
	}
	o.mu.Lock()
	o.endedSessions = append(o.endedSessions, endedSession{clientID: cid, commonName: commonName, rx: rx, tx: tx})
	o.mu.Unlock()
}

// foldEndedSessionsLocked adds what each finished session moved after its last
// polled row into this poll's per-CN growth.
//
// Runs after the status rows have been folded in, so a row still carrying a
// departing client — the `status 3` reply may have been in flight when it left —
// has already advanced that session's baseline and is not counted twice. A
// session that both began and ended between two polls has no baseline at all,
// and counts in full.
//
// Caller holds o.mu.
func (o *OpenVPN) foldEndedSessionsLocked(perCN map[string]*clientStatus) {
	ended := o.endedSessions
	o.endedSessions = nil

	for _, fin := range ended {
		dRx, dTx := fin.rx, fin.tx
		if prev, ok := o.sessionSeen[fin.clientID]; ok {
			dRx = fin.rx - prev.BytesReceived
			dTx = fin.tx - prev.BytesSent
			delete(o.sessionSeen, fin.clientID)
		}
		// The disconnect totals and the status rows are the same counters, so a
		// negative difference is not expected; bill nothing rather than mistake
		// it for a fresh session and bill the whole thing again.
		if dRx < 0 {
			dRx = 0
		}
		if dTx < 0 {
			dTx = 0
		}
		if dRx == 0 && dTx == 0 {
			continue
		}
		agg := perCN[fin.commonName]
		if agg == nil {
			agg = &clientStatus{CommonName: fin.commonName}
			perCN[fin.commonName] = agg
		}
		agg.BytesReceived += dRx
		agg.BytesSent += dTx
	}
}

// collectStats reads `status 3` and accumulates per-CN cumulative counters.
//
// OpenVPN reports per-session (per ClientID) cumulative byte counts. A user (CN)
// may have several concurrent sessions (duplicate-cn) and reconnects create new
// ClientIDs. We accumulate each session's growth into a per-CN cumulative total
// and hand that to the tracker, which computes the reset-delta for the panel.
//
// Sessions that ended since the last poll are folded in from the queue their
// disconnect events filled: their rows are already gone from `status 3`, so the
// poll alone would drop everything they moved after the previous tick.
func (o *OpenVPN) collectStats() {
	if o.mgmt == nil {
		return
	}
	rows := o.mgmt.requestStatus(5 * time.Second)

	// Sum growth per CN across all live sessions since the last poll.
	perCN := make(map[string]*clientStatus)
	seenSessions := make(map[string]struct{})

	o.mu.Lock()
	for _, row := range rows {
		seenSessions[row.ClientID] = struct{}{}
		prev, ok := o.sessionSeen[row.ClientID]
		var dRx, dTx int64
		if ok {
			dRx = row.BytesReceived - prev.BytesReceived
			dTx = row.BytesSent - prev.BytesSent
			if dRx < 0 {
				dRx = row.BytesReceived
			}
			if dTx < 0 {
				dTx = row.BytesSent
			}
		} else {
			dRx = row.BytesReceived
			dTx = row.BytesSent
		}
		o.sessionSeen[row.ClientID] = row

		agg := perCN[row.CommonName]
		if agg == nil {
			agg = &clientStatus{CommonName: row.CommonName, RealAddress: row.RealAddress}
			perCN[row.CommonName] = agg
		}
		agg.BytesReceived += dRx
		agg.BytesSent += dTx
		if row.RealAddress != "" {
			agg.RealAddress = row.RealAddress
		}
	}
	o.foldEndedSessionsLocked(perCN)

	// Drop sessions that disappeared between polls without a disconnect event
	// (the daemon died, or the event was missed): their tail is unrecoverable,
	// but their baseline must not linger.
	for cid := range o.sessionSeen {
		if _, ok := seenSessions[cid]; !ok {
			delete(o.sessionSeen, cid)
		}
	}
	// Fold per-poll growth into a per-CN cumulative counter for the tracker.
	if o.cnCumulative == nil {
		o.cnCumulative = make(map[string]*clientStatus)
	}
	var samples []stats.Sample
	for cn, growth := range perCN {
		cum := o.cnCumulative[cn]
		if cum == nil {
			cum = &clientStatus{CommonName: cn}
			o.cnCumulative[cn] = cum
		}
		cum.BytesReceived += growth.BytesReceived
		cum.BytesSent += growth.BytesSent
		samples = append(samples, stats.Sample{
			PublicKey:  cn, // tracker key = common name = user id
			Email:      cn,
			Rx:         cum.BytesReceived,
			Tx:         cum.BytesSent,
			EndpointIP: extractIP(growth.RealAddress),
		})
		// Node-level running totals (separate from the per-user tracker).
		o.totalRx += growth.BytesReceived
		o.totalTx += growth.BytesSent
	}
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}
}

func extractIP(realAddress string) string {
	// RealAddress is "ip:port"; strip the port. IPv6 is bracketed.
	if realAddress == "" {
		return ""
	}
	if realAddress[0] == '[' {
		if end := indexByte(realAddress, ']'); end > 0 {
			return realAddress[1:end]
		}
		return realAddress
	}
	if idx := lastIndexByte(realAddress, ':'); idx > 0 {
		return realAddress[:idx]
	}
	return realAddress
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func (o *OpenVPN) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
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
		// Node-level traffic = sum of all user traffic, tracked separately so this
		// poll does not drain the per-user deltas consumed by UsersStat.
		o.mu.Lock()
		totalRx, totalTx := o.totalRx, o.totalTx
		o.mu.Unlock()
		dRx, dTx := o.interfaceStats.Delta(totalRx, totalTx, request.GetReset_())
		return &common.StatResponse{
			Stats: stats.BuildInterfaceStats(o.config.InboundTag, "outbound", dRx, dTx),
		}, nil
	default:
		return nil, errors.New("unsupported stat type for openvpn")
	}
}

func (o *OpenVPN) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
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

func (o *OpenVPN) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}
	response := &common.StatsOnlineIpListResponse{Name: email, Ips: make(map[string]int64)}
	for ip, ts := range o.statsTracker.EndpointActivity([]string{email}) {
		response.Ips[ip] = ts
	}
	return response, nil
}

func (o *OpenVPN) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}

func (o *OpenVPN) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	if state != lifecycleRunning {
		return nil, errNotStarted
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        memStats.NumGC,
		Alloc:        memStats.Alloc,
		TotalAlloc:   memStats.TotalAlloc,
		Sys:          memStats.Sys,
		Mallocs:      memStats.Mallocs,
		Frees:        memStats.Frees,
		LiveObjects:  memStats.Mallocs - memStats.Frees,
		PauseTotalNs: memStats.PauseTotalNs,
		Uptime:       uint32(time.Since(o.startTime).Seconds()),
	}, nil
}
