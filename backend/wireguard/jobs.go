package wireguard

import (
	"context"
	"log"
	"time"

	"github.com/pasarguard/node/pkg/stats"
)

const statsDeviceErrorLogInterval = time.Minute

// initStatsTickers initializes stats update tickers
func (wg *WireGuard) initStatsTickers(ctx context.Context) {
	wg.updateInterval = time.Duration(wg.cfg.StatsUpdateIntervalSeconds) * time.Second
	cleanupInterval := time.Duration(wg.cfg.StatsCleanupIntervalSeconds) * time.Second

	wg.updateTicker = time.NewTicker(wg.updateInterval)
	wg.cleanupTicker = time.NewTicker(cleanupInterval)

	go wg.runStatsUpdateLoop(ctx)
}

// runStatsUpdateLoop runs the stats update loop
func (wg *WireGuard) runStatsUpdateLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-wg.updateTicker.C:
			wg.updateConnectedPeers(ctx)
		case <-wg.cleanupTicker.C:
			wg.cleanupOfflineUsers(ctx)
		}
	}
}

// updateConnectedPeers updates stats for connected users only
func (wg *WireGuard) updateConnectedPeers(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	wg.mu.RLock()
	mgr := wg.manager
	cfg := wg.config
	wg.mu.RUnlock()

	if mgr == nil || cfg == nil {
		return
	}

	device, err := mgr.GetDevice()
	if err != nil {
		wg.logStatsDeviceReadError(err)
		return
	}

	activeHandshakeCutoff := time.Now().Add(-onlineActivityThreshold)

	emailByKey := wg.peerStore.GetEmailMap()
	samples := make([]stats.Sample, 0, len(device.Peers))
	deviceKeys := make(map[string][]string, len(device.Peers))

	for _, peer := range device.Peers {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if peer.LastHandshakeTime.IsZero() {
			continue // never connected
		}
		if peer.LastHandshakeTime.Before(activeHandshakeCutoff) {
			continue // stale/offline peer
		}

		peerKey := peer.PublicKey.String()
		email, ok := emailByKey[peerKey]
		if !ok {
			continue // unknown peer, skip
		}

		endpointIP := ""
		// The device limit counts endpoints including the source port, because
		// clients reaching this node through a relay all share one address:
		// counting bare IPs would see every user's devices as a single one and
		// silently never enforce the limit. Stats and the panel keep the plain
		// IP — the port is meaningless to a human reading a device list.
		endpointKey := ""
		if peer.Endpoint != nil {
			endpointIP = peer.Endpoint.IP.String()
			endpointKey = peer.Endpoint.String()
		}

		deviceKeys[email] = append(deviceKeys[email], endpointKey)

		samples = append(samples, stats.Sample{
			PublicKey:  peerKey,
			Email:      email,
			Rx:         peer.ReceiveBytes,
			Tx:         peer.TransmitBytes,
			EndpointIP: endpointIP,
		})
	}

	wg.statsTracker.UpdateStatsBatch(samples)

	// Feed this poll's endpoints into the device-limit enforcer.
	activeIPs := make(map[string]map[string]struct{}, len(deviceKeys))
	for email, keys := range deviceKeys {
		for _, key := range keys {
			if key == "" {
				continue
			}
			set := activeIPs[email]
			if set == nil {
				set = make(map[string]struct{})
				activeIPs[email] = set
			}
			set[key] = struct{}{}
		}
	}
	wg.enforceIpLimits(mgr, activeIPs)
}

func (wg *WireGuard) logStatsDeviceReadError(err error) {
	now := time.Now()

	wg.mu.Lock()
	if !wg.lastStatsErrAt.IsZero() && now.Sub(wg.lastStatsErrAt) < statsDeviceErrorLogInterval {
		wg.mu.Unlock()
		return
	}
	wg.lastStatsErrAt = now
	wg.mu.Unlock()

	log.Printf("wireguard stats update skipped: failed to read device: %v", err)
	wg.emitWarningLogf("wireguard stats update skipped: failed to read device: %v", err)
}

// cleanupOfflineUsers removes deleted stats entries once their traffic has been reported.
func (wg *WireGuard) cleanupOfflineUsers(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
		wg.statsTracker.CleanupDeletedEntries()
	}
}
