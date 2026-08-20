package singbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pasarguard/node/backend/singbox/statsapi"
	"github.com/pasarguard/node/common"
)

// statsClient talks to sing-box's v2ray_api. Separate from the clash_api client
// on purpose: users go over HTTP, usage comes back over gRPC, and they are
// different endpoints in the config.
type statsClient struct {
	target string

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client statsapi.StatsServiceClient

	// Counters read out of sing-box but not yet handed to whoever asked for
	// them. See collect: sing-box resets everything or nothing, so this is
	// where the counters nobody asked for wait for the caller who wants them.
	pendingMu sync.Mutex
	pending   map[string]int64
}

func newStatsClient(target string) *statsClient {
	return &statsClient{target: target, pending: make(map[string]int64)}
}

// collect drains sing-box's counters into pending.
//
// sing-box ignores the query pattern and answers with every counter it holds,
// and its reset is all-or-nothing to match. So a poll for one kind of counter
// zeroes every other kind at the same time — and the counters the caller did
// not ask for are not merely skipped, they are destroyed.
//
// The panel polls user usage every 10s and outbound usage every 30s, both
// resetting. Each poll therefore threw away whatever the other had not read
// yet, and a user's traffic vanished whenever the outbound poll landed first:
// a full megabyte at a time, attributed to nobody, with every part of the
// system reporting success.
//
// So the reset happens exactly once, here, and everything it returns is kept.
// A caller then takes only its own counters, and the rest stay for theirs.
func (s *statsClient) collect(ctx context.Context) error {
	stats, err := s.query(ctx, "", true)
	if err != nil {
		return err
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for _, stat := range stats {
		s.pending[stat.GetName()] += stat.GetValue()
	}
	return nil
}

// take returns the pending counters matching prefix, removing them if the
// caller is consuming them. A caller that is only looking leaves them for the
// one that bills from them.
func (s *statsClient) take(prefix string, consume bool) map[string]int64 {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	out := make(map[string]int64)
	for name, value := range s.pending {
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		out[name] = value
		if consume {
			delete(s.pending, name)
		}
	}
	return out
}

// dial connects lazily. The stats endpoint is only used when the panel polls,
// which may be long after start, and a connection made eagerly would just be a
// connection to keep alive for nothing.
func (s *statsClient) dial(ctx context.Context) (statsapi.StatsServiceClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	conn, err := grpc.NewClient(s.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("singbox: dial stats api: %w", err)
	}
	s.conn = conn
	s.client = statsapi.NewStatsServiceClient(conn)
	return s.client, nil
}

func (s *statsClient) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
		s.client = nil
	}
}

func (s *statsClient) query(ctx context.Context, pattern string, reset bool) ([]*statsapi.Stat, error) {
	client, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.QueryStats(ctx, &statsapi.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, err
	}
	return resp.GetStat(), nil
}

// GetStats answers the panel's usage poll.
//
// sing-box names its counters exactly as xray does —
// user>>>NAME>>>traffic>>>uplink — so the shape handed back here is the one the
// panel already parses, and nothing downstream has to know which core produced
// it.
func (s *SingBox) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if s.stats == nil {
		return &common.StatResponse{}, nil
	}

	var pattern string
	switch request.GetType() {
	case common.StatType_UsersStat:
		pattern = "user>>>"
	case common.StatType_UserStat:
		pattern = "user>>>" + request.GetName() + ">>>"
	case common.StatType_Inbounds:
		pattern = "inbound>>>"
	case common.StatType_Inbound:
		pattern = "inbound>>>" + request.GetName() + ">>>"
	case common.StatType_Outbounds:
		pattern = "outbound>>>"
	case common.StatType_Outbound:
		pattern = "outbound>>>" + request.GetName() + ">>>"
	default:
		pattern = ""
	}

	// Everything sing-box has is drained into pending first, then this caller
	// takes only its own share. Filtering sing-box's answer directly would drop
	// counters it has already zeroed — which is data loss, not a filter.
	if err := s.stats.collect(ctx); err != nil {
		return nil, err
	}
	stats := s.stats.take(pattern, request.GetReset_())

	response := &common.StatResponse{Stats: make([]*common.Stat, 0, len(stats))}
	for rawName, value := range stats {
		name, kind, link := splitStatName(rawName)
		response.Stats = append(response.Stats, &common.Stat{
			Name:  name,
			Type:  kind,
			Link:  link,
			Value: value,
		})
	}
	return response, nil
}

// splitStatName breaks "user>>>alice>>>traffic>>>downlink" into the three
// fields the panel expects, in the SAME slots xray's parseStatName fills:
// Name = the entity ("alice"), Type = the direction ("downlink"), Link =
// "traffic". The panel decides up vs down by Type == "uplink"/"downlink", so
// putting the counter category ("user"/"inbound"/"outbound") there — as an
// earlier version did — made it count every sing-box outbound byte as
// downlink and drop per-inbound counters entirely. Anything that does not
// match the four-part shape is passed through under its own name rather than
// dropped, so an unexpected counter is visible instead of silently missing.
func splitStatName(raw string) (name, kind, link string) {
	parts := strings.Split(raw, ">>>")
	if len(parts) != 4 {
		return raw, "", ""
	}
	return parts[1], parts[3], parts[2]
}

// GetSysStats reports process-level numbers. sing-box does not expose the
// runtime detail xray does, so only uptime is real; the rest stay zero rather
// than being invented.
func (s *SingBox) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	s.mu.RLock()
	start := s.startTime
	s.mu.RUnlock()

	var uptime uint32
	if !start.IsZero() {
		uptime = uint32(time.Since(start).Seconds())
	}
	return &common.BackendStatsResponse{Uptime: uptime}, nil
}

// The three calls below have no sing-box equivalent.
//
// They return empty rather than an error on purpose: Composite fans every call
// across all backends on the node, so an error here would make an optional
// capability look like a broken node.

func (s *SingBox) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{}, nil
}

func (s *SingBox) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{Name: email}, nil
}

func (s *SingBox) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{Name: email}, nil
}
