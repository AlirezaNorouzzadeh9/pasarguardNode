package controller

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/ikev2"
	"github.com/pasarguard/node/backend/openvpn"
	"github.com/pasarguard/node/backend/wireguard"
	"github.com/pasarguard/node/backend/xray"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
	"github.com/pasarguard/node/pkg/sysstats"
)

const NodeVersion = "0.5.2"

type Service interface {
	Disconnect()
}

type Controller struct {
	// backends holds every core running on this node, keyed by backend type,
	// so one node can serve e.g. openvpn + ikev2 at the same time.
	backends    map[common.BackendType]backend.Backend
	cfg         *config.Config
	apiPort     int
	metricPort  int
	clientIP    string
	lastRequest time.Time
	stats       *common.SystemStatsResponse
	cancelFunc  context.CancelFunc
	mu          sync.RWMutex
}

func New(cfg *config.Config) *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		cfg:        cfg,
		backends:   make(map[common.BackendType]backend.Backend),
		apiPort:    netutil.FindFreePort(),
		metricPort: netutil.FindFreePort(),
		cancelFunc: cancel,
	}
}

func (c *Controller) ApiKey() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.ApiKey
}

func (c *Controller) Connect(ip string, keepAlive uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
	c.clientIP = ip

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	go c.recordSystemStats(ctx)
	if keepAlive > 0 {
		go c.keepAliveTracker(ctx, time.Duration(keepAlive)*time.Second)
	}
}

func (c *Controller) Disconnect() {
	c.cancelFunc()

	c.mu.Lock()
	backends := make([]backend.Backend, 0, len(c.backends))
	for _, b := range c.backends {
		backends = append(backends, b)
	}
	c.mu.Unlock()

	// Shutdown backends outside of lock to avoid deadlock.
	// Shutdown() will wait for process termination to complete.
	for _, b := range backends {
		b.Shutdown()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.backends = make(map[common.BackendType]backend.Backend)
	c.apiPort = netutil.FindFreePort()
	c.metricPort = netutil.FindFreePort()
	c.clientIP = ""
}

func (c *Controller) Ip() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
}

// StartBackend brings up (or replaces) the backend for a given type and adds it
// to the node's backend set. Calling it repeatedly with different types lets one
// node run several cores side by side; calling it again for the same type shuts
// the old instance down and swaps in the new one.
func (c *Controller) StartBackend(ctx context.Context, backendCfg *common.Backend) error {
	var newBackend backend.Backend

	switch backendCfg.GetType() {
	case common.BackendType_XRAY:
		config, err := xray.NewConfig(backendCfg.GetConfig(), backendCfg.GetExcludeInbounds())
		if err != nil {
			return err
		}

		newBackend, err = xray.New(
			ctx,
			config,
			backendCfg.GetUsers(),
			c.apiPort,
			c.metricPort,
			c.cfg,
		)
		if err != nil {
			return err
		}

	case common.BackendType_WIREGUARD:
		if err := wireguard.CheckDeps(); err != nil {
			return err
		}
		config, err := wireguard.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = wireguard.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}

	case common.BackendType_OPENVPN:
		if err := openvpn.CheckDeps(); err != nil {
			return err
		}
		config, err := openvpn.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = openvpn.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}

	case common.BackendType_IKEV2:
		if err := ikev2.CheckDeps(); err != nil {
			return err
		}
		config, err := ikev2.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = ikev2.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid backend type")
	}

	c.mu.Lock()
	old := c.backends[backendCfg.GetType()]
	c.backends[backendCfg.GetType()] = newBackend
	c.mu.Unlock()

	// Replace-by-type: tear down a previous instance of the same core.
	if old != nil {
		old.Shutdown()
	}

	return nil
}

// Backend returns a composite view over every core running on this node, so the
// rpc/rest handlers can keep operating on a single backend.Backend.
func (c *Controller) Backend() backend.Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.backends) == 0 {
		return nil
	}
	list := make([]backend.Backend, 0, len(c.backends))
	for _, b := range c.backends {
		list = append(list, b)
	}
	composite := backend.NewComposite(list)
	if composite == nil {
		return nil
	}
	return composite
}

func (c *Controller) keepAliveTracker(ctx context.Context, keepAlive time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			lastRequest := c.lastRequest
			c.mu.RUnlock()
			if time.Since(lastRequest) >= keepAlive {
				log.Println("disconnect automatically due to keep alive timeout")
				c.Disconnect()
			}
		}
	}
}

func (c *Controller) recordSystemStats(ctx context.Context) {
	interval := 1500 * time.Millisecond

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	collect := func() {
		stats, err := sysstats.GetSystemStats()
		if err != nil {
			log.Printf("Failed to get system stats: %v", err)
			return
		}

		c.mu.Lock()
		c.stats = stats
		c.mu.Unlock()
	}

	collect()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}

func (c *Controller) SystemStats(ctx context.Context) *common.SystemStatsResponse {
	c.mu.RLock()
	statsSnapshot := c.stats
	c.mu.RUnlock()

	backendSnapshot := c.Backend()

	response := &common.SystemStatsResponse{}
	if statsSnapshot != nil {
		response = &common.SystemStatsResponse{
			MemTotal:               statsSnapshot.GetMemTotal(),
			MemUsed:                statsSnapshot.GetMemUsed(),
			CpuCores:               statsSnapshot.GetCpuCores(),
			CpuUsage:               statsSnapshot.GetCpuUsage(),
			IncomingBandwidthSpeed: statsSnapshot.GetIncomingBandwidthSpeed(),
			OutgoingBandwidthSpeed: statsSnapshot.GetOutgoingBandwidthSpeed(),
			Uptime:                 statsSnapshot.GetUptime(),
		}
	}

	if backendSnapshot == nil {
		return response
	}

	// Backend uptime is owned by each backend implementation; controller only forwards it here.
	backendStats, err := backendSnapshot.GetSysStats(ctx)
	if err != nil {
		log.Printf("Failed to get backend uptime for system stats: %v", err)
		return response
	}

	response.Uptime = uint64(backendStats.GetUptime())
	return response
}

func (c *Controller) BaseInfoResponse() *common.BaseInfoResponse {
	back := c.Backend()

	response := &common.BaseInfoResponse{
		Started:           false,
		CoreVersion:       "",
		NodeVersion:       NodeVersion,
		AvailableBackends: availableBackends(),
	}

	if back != nil {
		response.Started = back.Started()
		response.CoreVersion = back.Version()
	}

	return response
}

// availableBackends reports which backend types this node can actually run,
// based on whether their OS-level dependencies are installed. xray needs none;
// the others are probed via each backend's CheckDeps. The panel uses this to
// grey out cores a node cannot serve.
func availableBackends() []common.BackendType {
	out := []common.BackendType{common.BackendType_XRAY}
	if openvpn.CheckDeps() == nil {
		out = append(out, common.BackendType_OPENVPN)
	}
	if wireguard.CheckDeps() == nil {
		out = append(out, common.BackendType_WIREGUARD)
	}
	if ikev2.CheckDeps() == nil {
		out = append(out, common.BackendType_IKEV2)
	}
	return out
}

func (c *Controller) OutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	backendSnapshot := c.Backend()

	if backendSnapshot == nil {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	return backendSnapshot.GetOutboundsLatency(ctx, request)
}
