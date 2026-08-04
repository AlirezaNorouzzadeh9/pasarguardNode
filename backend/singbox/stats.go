package singbox

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pasarguard/node/common"
)

// statsClient talks to sing-box's V2Ray-compatible stats service.
//
// sing-box speaks the same StatsService as xray, so counter names follow the
// familiar shape:
//
//	user>>>{email}>>>traffic>>>{uplink|downlink}
//	inbound>>>{tag}>>>traffic>>>{uplink|downlink}
type statsClient struct {
	addr string

	mu   sync.Mutex
	conn *grpc.ClientConn
}

func newStatsClient(addr string) *statsClient {
	return &statsClient{addr: addr}
}

func (c *statsClient) dial(ctx context.Context) (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

func (c *statsClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// GetSysStats reports this process's runtime numbers. sing-box runs inside the
// node, so these are the node's own — which is what the panel shows for a
// backend that has no separate process to measure.
func (s *SingBox) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
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
		Uptime:       uint32(time.Since(s.startTime).Seconds()),
	}, nil
}

// GetStats returns traffic counters. The panel asks for users, inbounds or
// outbounds; sing-box counts the first two.
func (s *SingBox) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if !s.Started() {
		return nil, errNotStarted
	}
	pattern := ""
	switch request.GetType() {
	case common.StatType_UsersStat:
		pattern = "user>>>"
	case common.StatType_Inbounds:
		pattern = "inbound>>>"
	case common.StatType_Outbounds:
		pattern = "outbound>>>"
	case common.StatType_UserStat:
		pattern = "user>>>" + request.GetName() + ">>>"
	case common.StatType_Inbound:
		pattern = "inbound>>>" + request.GetName() + ">>>"
	case common.StatType_Outbound:
		pattern = "outbound>>>" + request.GetName() + ">>>"
	}

	stats, err := s.queryStats(ctx, pattern, request.GetReset_())
	if err != nil {
		return nil, err
	}
	return &common.StatResponse{Stats: stats}, nil
}

// GetUserOnlineStats reports how many connections a user currently has.
//
// sing-box's stats service exposes traffic counters but no online-session
// gauge, so this reports zero rather than an invented number — the panel treats
// a zero from one backend as "nothing to add" when merging across backends.
func (s *SingBox) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	if !s.Started() {
		return nil, errNotStarted
	}
	return &common.OnlineStatResponse{Name: email, Value: 0}, nil
}

// GetUserOnlineIpListStats reports the addresses a user is connected from.
// Same limitation as above: sing-box does not expose per-user peer addresses.
func (s *SingBox) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	if !s.Started() {
		return nil, errNotStarted
	}
	return &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}, nil
}

// splitCounterName turns "user>>>alice>>>traffic>>>uplink" into its parts.
func splitCounterName(name string) (kind, id, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[3], true
}
