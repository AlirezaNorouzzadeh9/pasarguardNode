package singbox

import (
	"context"

	"github.com/xtls/xray-core/app/stats/command"

	"github.com/pasarguard/node/common"
)

// queryStats reads counters from sing-box's V2Ray-compatible stats service.
//
// The xray-core generated client is reused deliberately: sing-box implements
// the same StatsService wire contract, and xray-core is already a dependency,
// so this needs no second copy of the stubs.
func (s *SingBox) queryStats(ctx context.Context, pattern string, reset bool) ([]*common.Stat, error) {
	if s.stats == nil {
		return nil, errNotStarted
	}
	conn, err := s.stats.dial(ctx)
	if err != nil {
		return nil, err
	}
	client := command.NewStatsServiceClient(conn)
	resp, err := client.QueryStats(ctx, &command.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, err
	}

	out := make([]*common.Stat, 0, len(resp.GetStat()))
	for _, st := range resp.GetStat() {
		kind, id, direction, ok := splitCounterName(st.GetName())
		if !ok {
			continue
		}
		out = append(out, &common.Stat{
			Name:  id,
			Type:  kind,
			Link:  direction,
			Value: st.GetValue(),
		})
	}
	return out, nil
}
