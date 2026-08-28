package wireguard

import (
	"github.com/pasarguard/node/backend/ratelimit"
	"github.com/pasarguard/node/common"
)

// recordSpeeds notes each synced user's speed limit. full replaces the whole
// map (an authoritative sync), a partial update only upserts — a user absent
// from a partial batch keeps the cap they already had.
func (wg *WireGuard) recordSpeeds(users []*common.User, full bool) {
	wg.speedMu.Lock()
	defer wg.speedMu.Unlock()
	if full || wg.userSpeed == nil {
		wg.userSpeed = make(map[string]uint32, len(users))
	}
	for _, u := range users {
		if email := u.GetEmail(); email != "" {
			wg.userSpeed[email] = u.GetSpeedLimit()
		}
	}
}

// ShapedClients lists this backend's peers that carry a speed limit, together
// with their tunnel addresses, for the node's traffic shaper. WireGuard peers
// have fixed tunnel addresses, so every configured peer with a limit is
// returned regardless of whether it is currently connected.
func (wg *WireGuard) ShapedClients() []ratelimit.Client {
	wg.speedMu.Lock()
	speed := make(map[string]uint32, len(wg.userSpeed))
	for email, kbps := range wg.userSpeed {
		speed[email] = kbps
	}
	wg.speedMu.Unlock()

	var clients []ratelimit.Client
	for _, peer := range wg.peerStore.GetAll() {
		limit := speed[peer.Email]
		if limit == 0 {
			continue
		}
		for _, ipnet := range peer.AllowedIPs {
			clients = append(clients, ratelimit.Client{
				User:      peer.Email,
				Address:   ipnet.IP.String(),
				LimitKbps: limit,
			})
		}
	}
	return clients
}
