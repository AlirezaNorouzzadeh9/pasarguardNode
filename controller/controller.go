package controller

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/wireguard"
	"github.com/pasarguard/node/backend/xray"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
	"github.com/pasarguard/node/pkg/sysstats"
)

const NodeVersion = "0.5.3"

type Service interface {
	Disconnect()
}

// backendKey identifies one running core. Keying by type alone would allow only
// a single core per protocol, but a node may need several — e.g. two WireGuard
// cores serving different exit subnets. The instance part comes from the core
// config (see backendInstanceID), so the panel can assign several cores of the
// same type and each gets its own backend.
type backendKey struct {
	typ      common.BackendType
	instance string
}

type Controller struct {
	// backends holds every core running on this node, keyed by type+instance.
	backends    map[backendKey]backend.Backend
	cfg         *config.Config
	apiPort     int
	metricPort  int
	clientIP    string
	lastRequest time.Time
	stats       *common.SystemStatsResponse
	cancelFunc  context.CancelFunc
	mu          sync.RWMutex
	controlMu   sync.Mutex
}

func New(cfg *config.Config) *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		cfg:        cfg,
		backends:   make(map[backendKey]backend.Backend),
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
	running := make([]backend.Backend, 0, len(c.backends))
	for _, b := range c.backends {
		running = append(running, b)
	}
	c.mu.Unlock()

	// Shutdown backends outside of lock to avoid deadlock
	// Shutdown() will wait for process termination to complete
	for _, b := range running {
		b.Shutdown()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.backends = make(map[backendKey]backend.Backend)
	c.apiPort = netutil.FindFreePort()
	c.metricPort = netutil.FindFreePort()
	c.clientIP = ""
}

func (c *Controller) Ip() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

func (c *Controller) IsCurrentClient(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP == "" || c.clientIP == ip
}

func (c *Controller) LockControl() {
	c.controlMu.Lock()
}

func (c *Controller) UnlockControl() {
	c.controlMu.Unlock()
}

func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
}

// StartBackend brings a core up and adds it to the node's backend set. Cores are
// tracked per type+instance, so a node can run several side by side — different
// protocols, and also several cores of the same protocol, such as two WireGuard
// interfaces with different exit subnets. Calling it again for the same instance
// retires the old one and swaps the new one in; cores under a different key keep
// serving.
func (c *Controller) StartBackend(ctx context.Context, backendCfg *common.Backend) error {
	key := backendKey{
		typ:      backendCfg.GetType(),
		instance: backendInstanceID(backendCfg.GetType(), backendCfg.GetConfig()),
	}

	// Retire a previous instance of this exact core *before* launching the new
	// one: the replacement reuses the same listen port and on-disk state, so
	// letting the two overlap makes the new one fail to bind.
	c.mu.Lock()
	old := c.backends[key]
	delete(c.backends, key)
	c.mu.Unlock()
	if old != nil {
		old.Shutdown()
	}

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
		config, err := wireguard.NewConfig(backendCfg.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err = wireguard.New(c.cfg, config, backendCfg.GetUsers())
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid backend type")
	}

	c.mu.Lock()
	c.backends[key] = newBackend
	c.mu.Unlock()

	return nil
}

// backendInstanceID pulls the identifier that distinguishes two cores of the
// same type out of the core config the panel sent. WireGuard is identified by
// its interface name, which already scopes its kernel device and on-disk state,
// so instances never collide. Xray is deliberately left unkeyed: one xray
// process serves every inbound, so a second xray core replaces the first.
//
// An unparseable or nameless config falls back to "", restoring the old
// replace-by-type behaviour rather than silently starting a duplicate.
func backendInstanceID(t common.BackendType, configStr string) string {
	var field string
	switch t {
	case common.BackendType_WIREGUARD:
		field = "interface_name"
	default:
		return ""
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(configStr), &parsed); err != nil {
		return ""
	}
	if v, ok := parsed[field].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
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

// anyBackend returns one running backend without allocating a composite, for
// the read-only paths that only need "is anything up". It takes no lock of its
// own — callers must already hold c.mu.
func (c *Controller) anyBackend() backend.Backend {
	for _, b := range c.backends {
		return b
	}
	return nil
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
	backendSnapshot := c.anyBackend()
	c.mu.RUnlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

	response := &common.BaseInfoResponse{
		Started:     false,
		CoreVersion: "",
		NodeVersion: NodeVersion,
	}

	if b := c.anyBackend(); b != nil {
		response.Started = b.Started()
		response.CoreVersion = b.Version()
	}

	return response
}

func (c *Controller) OutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	// The composite, not any single backend: latency is an xray feature, and
	// picking one core at random could hand back the WireGuard one and report
	// no outbounds at all.
	backendSnapshot := c.Backend()

	if backendSnapshot == nil {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	return backendSnapshot.GetOutboundsLatency(ctx, request)
}
