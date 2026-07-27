package l2tp

import "github.com/pasarguard/node/backend/ratelimit"

// ShapedClients lists connected L2TP clients that carry a speed limit, paired
// with their assigned pool address, for the node's shaper.
//
// TODO(live): like the accounting poll, this needs the pppd session→username
// map (each client gets a ppp<N> interface and a pool IP). It is filled in once
// the tunnel is confirmed working on a real node; until then no L2TP client is
// shaped.
func (o *L2TP) ShapedClients() []ratelimit.Client { return nil }
