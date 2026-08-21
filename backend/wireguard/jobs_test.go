package wireguard

import (
	"context"
	"testing"
	"time"

	"github.com/pasarguard/node/config"
	pkgstats "github.com/pasarguard/node/pkg/stats"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A peer with an old handshake is still sampled.
//
// WireGuard rekeys roughly every two minutes while data flows, so a peer
// downloading at full rate has a handshake older than the 45s online threshold
// for most of its life. Skipping those peers meant their counters were not read
// at all: the panel showed them offline mid-transfer, and everything they moved
// between the last accepted sample and their removal was never billed.
func TestUpdateConnectedPeersSamplesPeersWithStaleHandshakes(t *testing.T) {
	_, recentPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recent key pair: %v", err)
	}
	_, stalePub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate stale key pair: %v", err)
	}
	_, neverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate never-connected key pair: %v", err)
	}

	recentKey, err := wgtypes.ParseKey(recentPub)
	if err != nil {
		t.Fatalf("failed to parse recent public key: %v", err)
	}
	staleKey, err := wgtypes.ParseKey(stalePub)
	if err != nil {
		t.Fatalf("failed to parse stale public key: %v", err)
	}
	neverKey, err := wgtypes.ParseKey(neverPub)
	if err != nil {
		t.Fatalf("failed to parse never-connected public key: %v", err)
	}

	now := time.Now()
	manager := &Manager{
		iFaceName: "wg-test",
		client: &fakeWGClient{
			deviceFn: func(_ string) (*wgtypes.Device, error) {
				return &wgtypes.Device{Peers: []wgtypes.Peer{
					{
						PublicKey:         recentKey,
						LastHandshakeTime: now,
						ReceiveBytes:      120,
						TransmitBytes:     80,
					},
					{
						// Mid-transfer, but two minutes since the last rekey.
						PublicKey:         staleKey,
						LastHandshakeTime: now.Add(-onlineActivityThreshold - time.Second),
						ReceiveBytes:      300,
						TransmitBytes:     200,
					},
					{
						// Configured but never used: nothing to account for.
						PublicKey: neverKey,
					},
				}}, nil
			},
		},
	}

	peerStore := NewPeerStore()
	peerStore.Init([]*PeerInfo{
		{Email: "recent@example.com", PublicKey: recentKey},
		{Email: "stale@example.com", PublicKey: staleKey},
		{Email: "never@example.com", PublicKey: neverKey},
	})

	wg := &WireGuard{
		manager:      manager,
		cfg:          &config.Config{},
		config:       &Config{},
		peerStore:    peerStore,
		statsTracker: pkgstats.New(),
	}

	wg.updateConnectedPeers(context.Background())

	entries := wg.statsTracker.GetStatsEntries([]string{recentKey.String(), staleKey.String(), neverKey.String()})
	if _, ok := entries[staleKey.String()]; !ok {
		t.Fatal("peer with an old handshake was not sampled; its traffic is invisible until it rekeys")
	}
	if _, ok := entries[recentKey.String()]; !ok {
		t.Fatal("recently handshaked peer was not sampled")
	}
	if _, ok := entries[neverKey.String()]; ok {
		t.Fatal("peer that never completed a handshake should not be tracked")
	}

	byUser := map[string]int64{}
	for _, stat := range wg.statsTracker.GetUsersStats(context.Background(), false).GetStats() {
		byUser[stat.GetName()] += stat.GetValue()
	}
	if byUser["stale@example.com"] != 500 {
		t.Fatalf("stale peer billed %d bytes, want 300+200", byUser["stale@example.com"])
	}
	if byUser["recent@example.com"] != 200 {
		t.Fatalf("recent peer billed %d bytes, want 120+80", byUser["recent@example.com"])
	}
}

// The counters live in the kernel next to the peer, so a removal takes whatever
// it moved since the last poll with it unless it is read first.
func TestDepartingPeerIsSampledBeforeRemoval(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	key, err := wgtypes.ParseKey(pub)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	manager := &Manager{
		iFaceName: "wg-test",
		client: &fakeWGClient{
			deviceFn: func(_ string) (*wgtypes.Device, error) {
				return &wgtypes.Device{Peers: []wgtypes.Peer{
					{
						PublicKey:         key,
						LastHandshakeTime: time.Now().Add(-2 * time.Minute),
						ReceiveBytes:      4096,
						TransmitBytes:     8192,
					},
				}}, nil
			},
		},
	}

	peerStore := NewPeerStore()
	peerStore.Init([]*PeerInfo{{Email: "leaving@example.com", PublicKey: key}})

	wg := &WireGuard{
		manager:      manager,
		cfg:          &config.Config{},
		config:       &Config{},
		peerStore:    peerStore,
		statsTracker: pkgstats.New(),
	}

	wg.sampleDepartingPeers([]string{key.String()})
	wg.statsTracker.RemoveStats(key.String())

	var total int64
	for _, stat := range wg.statsTracker.GetUsersStats(context.Background(), true).GetStats() {
		if stat.GetName() == "leaving@example.com" {
			total += stat.GetValue()
		}
	}
	if total != 12288 {
		t.Fatalf("removed peer billed %d bytes, want 4096+8192 — its last stretch was dropped with the peer", total)
	}
}
