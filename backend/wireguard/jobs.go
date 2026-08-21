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

	emailByKey := wg.peerStore.GetEmailMap()
	samples := make([]stats.Sample, 0, len(device.Peers))

	for _, peer := range device.Peers {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if peer.LastHandshakeTime.IsZero() {
			continue // never connected
		}
		// Every peer that has ever completed a handshake is sampled, however
		// old that handshake is. WireGuard only rekeys about every two minutes
		// while data flows, so a peer downloading at full rate spends most of
		// its time past any threshold shorter than that: skipping those peers
		// stopped their counters being read at all, which showed them offline
		// mid-transfer and dropped everything they moved between the last
		// accepted sample and their removal.
		//
		// Sampling everything costs nothing to accuracy: the tracker decides
		// activity from counter growth, not from being handed a sample, and it
		// ignores one whose values have not changed.

		peerKey := peer.PublicKey.String()
		email, ok := emailByKey[peerKey]
		if !ok {
			continue // unknown peer, skip
		}

		endpointIP := ""
		if peer.Endpoint != nil {
			endpointIP = peer.Endpoint.IP.String()
		}

		samples = append(samples, stats.Sample{
			PublicKey:  peerKey,
			Email:      email,
			Rx:         peer.ReceiveBytes,
			Tx:         peer.TransmitBytes,
			EndpointIP: endpointIP,
		})
	}

	wg.statsTracker.UpdateStatsBatch(samples)
}

// sampleDepartingPeers reads the counters of peers that are about to be removed
// and hands them to the tracker one last time.
//
// A peer's byte counts live in the kernel alongside the peer: the moment it is
// applied away, whatever it moved since the last poll is unrecoverable. The
// tracker keeps the pending delta of an entry it has been told to remove until
// the panel collects it, so a final sample taken here is still billed.
//
// Best effort by design — a device read that fails costs at most one poll
// interval of one departing peer's traffic, which is not worth failing a sync
// over.
func (wg *WireGuard) sampleDepartingPeers(keys []string) {
	if len(keys) == 0 {
		return
	}

	wg.mu.RLock()
	mgr := wg.manager
	wg.mu.RUnlock()
	if mgr == nil {
		return
	}

	device, err := mgr.GetDevice()
	if err != nil {
		return
	}

	departing := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		departing[key] = struct{}{}
	}

	emailByKey := wg.peerStore.GetEmailMap()
	samples := make([]stats.Sample, 0, len(keys))
	for _, peer := range device.Peers {
		peerKey := peer.PublicKey.String()
		if _, going := departing[peerKey]; !going {
			continue
		}
		email, ok := emailByKey[peerKey]
		if !ok {
			continue
		}
		samples = append(samples, stats.Sample{
			PublicKey: peerKey,
			Email:     email,
			Rx:        peer.ReceiveBytes,
			Tx:        peer.TransmitBytes,
		})
	}

	wg.statsTracker.UpdateStatsBatch(samples)
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
