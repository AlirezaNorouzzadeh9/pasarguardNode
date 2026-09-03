package singbox

import (
	"context"
	"fmt"
	"sort"
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
	// The cumulative value each counter last held, so collect can bill only the
	// growth since the previous read instead of resetting. See collect.
	baseline map[string]int64
}

func newStatsClient(target string) *statsClient {
	return &statsClient{target: target, pending: make(map[string]int64), baseline: make(map[string]int64)}
}

// collect folds the growth of sing-box's counters into pending.
//
// It reads them CUMULATIVELY — reset=false — and bills only the increase over
// the value each counter last held (the baseline). This replaces the old
// read-and-reset, which was unusable for two reasons that both cost real money:
//
//   - sing-box ignores the query pattern and its reset is all-or-nothing, so a
//     poll for one kind of counter destroyed every other kind at the same time;
//     a user's traffic vanished whenever the outbound poll landed first.
//
//   - a name's counter is not cleared when its user is removed, so if the same
//     name was created again the very next read billed the new account the old
//     holder's entire total at once — a phantom drain of a user who never even
//     connected to the node.
//
// A cumulative read fixes both: nothing is destroyed (no reset), and a re-used
// name keeps its baseline, so its delta is zero until it actually moves traffic
// again. First sight of a counter is baselined WITHOUT billing, precisely so an
// existing total is never charged to whoever the name belongs to now. A value
// that has dropped below its baseline means sing-box restarted (counters back to
// zero), so the whole current value is new traffic since that restart.
func (s *statsClient) collect(ctx context.Context) error {
	stats, err := s.query(ctx, "", false)
	if err != nil {
		return err
	}
	s.fold(stats)
	return nil
}

// fold turns cumulative counter values into billable growth against the
// baseline. Split out from collect so the accounting can be tested without a
// live sing-box.
func (s *statsClient) fold(stats []*statsapi.Stat) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.baseline == nil {
		s.baseline = make(map[string]int64)
	}
	for _, stat := range stats {
		name := stat.GetName()
		cur := stat.GetValue()
		prev, seen := s.baseline[name]
		s.baseline[name] = cur
		switch {
		case !seen:
			// First time seen: baseline only, never bill. A counter may already
			// hold a departed account's total.
		case cur < prev:
			// sing-box restarted; the counter reset. Everything it holds now is
			// new traffic since the restart.
			if cur > 0 {
				s.pending[name] += cur
			}
		default:
			if d := cur - prev; d > 0 {
				s.pending[name] += d
			}
		}
	}
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

// GetUserOnlineIpListStats reports where a user is connected from.
//
// The v2ray_api stats this backend reads for usage carry bytes and nothing
// else, so this comes from clash_api's live connection list instead: sing-box
// records the authenticated user and the source address of every connection,
// which is exactly the pair needed. Stock sing-box, no patch involved.
func (s *SingBox) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	response := &common.StatsOnlineIpListResponse{Name: email, Ips: make(map[string]int64)}

	conns, err := s.client.connections(ctx)
	if err != nil {
		// Reporting nothing is better than failing the panel's poll for every
		// other backend on this node.
		return response, nil
	}

	now := time.Now().Unix()
	for _, conn := range conns {
		if s.userOf(conn) != email {
			continue
		}
		if ip := conn.Metadata.SrcIP; ip != "" {
			response.Ips[ip] = now
		}
	}
	return response, nil
}

// userOf resolves the user a connection belongs to.
//
// sing-box names the authenticated user directly. It may also name the slot's
// placeholder for a user whose credentials have just been withdrawn, which
// belongs to nobody.
func (s *SingBox) userOf(conn clashConnection) string {
	name := conn.Metadata.User
	if name == "" || name == freeSlotName {
		return ""
	}
	return name
}

// enforceIPLimits closes the connections a user is over their limit by.
//
// The newest go: the connections already running belong to someone using the
// service, and closing one of those to make room for a newcomer interrupts the
// wrong person. Connections are grouped by source address rather than counted
// one by one — a single client opens many at once, and each is not a device.
func (s *SingBox) enforceIPLimits(ctx context.Context) {
	conns, err := s.client.connections(ctx)
	if err != nil {
		return
	}

	// user -> source ip -> the connections from it, and when it first appeared.
	perUser := make(map[string]map[string][]clashConnection)
	firstSeen := make(map[string]map[string]string)
	for _, conn := range conns {
		user := s.userOf(conn)
		ip := conn.Metadata.SrcIP
		if user == "" || ip == "" {
			continue
		}
		if perUser[user] == nil {
			perUser[user] = make(map[string][]clashConnection)
			firstSeen[user] = make(map[string]string)
		}
		perUser[user][ip] = append(perUser[user][ip], conn)
		if at, seen := firstSeen[user][ip]; !seen || conn.Start < at {
			firstSeen[user][ip] = conn.Start
		}
	}

	for user, byIP := range perUser {
		limit := s.limitFor(user)
		if limit == 0 || uint32(len(byIP)) <= limit {
			continue
		}

		addresses := make([]string, 0, len(byIP))
		for ip := range byIP {
			addresses = append(addresses, ip)
		}
		// Oldest first, so everything past the limit is the newest.
		sort.SliceStable(addresses, func(i, j int) bool {
			return firstSeen[user][addresses[i]] < firstSeen[user][addresses[j]]
		})

		for _, ip := range addresses[limit:] {
			for _, conn := range byIP[ip] {
				_ = s.client.closeConnection(ctx, conn.ID)
			}
			s.emitLogf("Info", "singbox: %s is over their %d-address limit; closed the newest (%s)", user, limit, ip)
		}
	}
}
