package ikev2

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

func (o *IKEv2) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(o.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.waitDone:
			return
		case <-ticker.C:
			o.poll()
		}
	}
}

func (o *IKEv2) poll() {
	sas, err := o.vici.listSAs()
	if err != nil {
		return
	}

	// Count SAs per identity (device-limit) and remember which ike ids to keep.
	perIdentitySAs := make(map[string][]saInfo)
	present := make(map[uint32]struct{})
	for _, sa := range sas {
		present[sa.IKEID] = struct{}{}
		perIdentitySAs[sa.Identity] = append(perIdentitySAs[sa.Identity], sa)
	}

	var samples []stats.Sample

	o.mu.Lock()
	// Accumulate byte deltas per identity across SA churn.
	growthRx := make(map[string]int64)
	growthTx := make(map[string]int64)
	for _, sa := range sas {
		last := o.saSeen[sa.IKEID]
		dRx := sa.BytesIn - last[0]
		dTx := sa.BytesOut - last[1]
		if dRx < 0 {
			dRx = sa.BytesIn
		}
		if dTx < 0 {
			dTx = sa.BytesOut
		}
		o.saSeen[sa.IKEID] = [2]int64{sa.BytesIn, sa.BytesOut}
		growthRx[sa.Identity] += dRx
		growthTx[sa.Identity] += dTx
	}
	// Drop SAs that are gone (their final bytes were already counted).
	for id := range o.saSeen {
		if _, ok := present[id]; !ok {
			delete(o.saSeen, id)
		}
	}
	now := time.Now().Unix()
	for identity, saList := range perIdentitySAs {
		o.cumRx[identity] += growthRx[identity]
		o.cumTx[identity] += growthTx[identity]
		o.totalRx += growthRx[identity]
		o.totalTx += growthTx[identity]
		endpoint := ""
		if len(saList) > 0 {
			endpoint = saList[0].Remote
		}
		samples = append(samples, stats.Sample{
			PublicKey:  identity,
			Email:      identity,
			Rx:         o.cumRx[identity],
			Tx:         o.cumTx[identity],
			EndpointIP: endpoint,
		})
		_ = now
	}
	o.mu.Unlock()

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}

	o.enforceDeviceLimits(perIdentitySAs)
}

// enforceDeviceLimits terminates the SAs that exceed a user's device limit.
func (o *IKEv2) enforceDeviceLimits(perIdentity map[string][]saInfo) {
	for identity, saList := range perIdentity {
		limit := o.users.limitFor(identity)
		if limit == 0 || uint32(len(saList)) <= limit {
			continue
		}
		for _, sa := range saList[limit:] {
			if err := o.vici.terminateIKE(sa.IKEID); err == nil {
				o.emitLogf("Info", "ikev2: user %s over device limit, terminating SA %d", identity, sa.IKEID)
			}
		}
	}
}

func (o *IKEv2) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
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
		return nil, errors.New("unsupported stat type for ikev2")
	}
}

func (o *IKEv2) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
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

func (o *IKEv2) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
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

func (o *IKEv2) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
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
