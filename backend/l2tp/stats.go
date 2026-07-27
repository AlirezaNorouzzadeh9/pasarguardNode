package l2tp

import (
	"context"
	"errors"
	"runtime"
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

// poll refreshes per-user accounting and the online-IP snapshot.
//
// TODO(live): L2TP accounting is collected per pppd session (one ppp<N>
// interface per client). Wiring it up needs a pppd ip-up/ip-down hook that maps
// the interface to the authenticated username; that is layered in once the
// tunnel itself is confirmed working on a real node, mirroring how IKEv2's
// limits were added after its connection path was proven.
func (o *L2TP) poll() {}

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
