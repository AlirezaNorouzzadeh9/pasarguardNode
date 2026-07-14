package ikev2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/stats"
)

var errNotStarted = errors.New("ikev2 not started")

var strongswanVersionRe = regexp.MustCompile(`strongSwan\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

// DetectVersion returns the installed strongSwan version via swanctl --version.
func DetectVersion() string {
	out, err := exec.Command(swanctlBinary, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if m := strongswanVersionRe.FindStringSubmatch(string(out)); len(m) == 2 {
		return m[1]
	}
	return "unknown"
}

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

const (
	onlineActivityThreshold = 60 * time.Second
	viciSocketPath          = "/var/run/charon.vici"
	charonBinary            = "/usr/lib/ipsec/charon"
	swanctlBinary           = "/usr/sbin/swanctl"
)

// CheckDeps reports whether strongSwan (charon + swanctl) is installed, so the
// panel gets a clear "not installed" error instead of a cryptic charon failure.
func CheckDeps() error {
	for _, p := range []string{charonBinary, swanctlBinary} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("strongSwan is not installed on this node (missing %s)", p)
		}
	}
	return nil
}

// IKEv2 implements backend.Backend by supervising a strongSwan charon process
// and driving it over swanctl/VICI. Auth is EAP-MSCHAPv2 (username/password).
type IKEv2 struct {
	config *Config
	cfg    *config.Config

	users          *userStore
	vici           *viciSession
	statsTracker   *stats.Tracker
	interfaceStats *stats.InterfaceCountersTracker
	totalRx        int64
	totalTx        int64

	// per-SA (IKE uniqueid) last-seen byte counters, to accumulate deltas across
	// SA churn (rekey/reconnect resets charon's per-SA counters).
	saSeen map[uint32][2]int64
	// per-identity cumulative byte counters fed to the stats tracker.
	cumRx map[string]int64
	cumTx map[string]int64

	process   *exec.Cmd
	waitDone  chan struct{}
	logChan   chan string
	cancel    context.CancelFunc
	startTime time.Time

	mu             sync.RWMutex
	state          lifecycleState
	shutdownOnce   sync.Once
	hostRouting    func()
	updateInterval time.Duration
}

// New creates and starts an IKEv2 backend.
func New(cfg *config.Config, ikConfig *Config, users []*common.User) (*IKEv2, error) {
	if ikConfig == nil {
		return nil, errors.New("ikev2 config must not be nil")
	}
	ikConfig.workDir = filepath.Join(cfg.GeneratedConfigPath, "ikev2", ikConfig.InboundTag)

	ctx, cancel := context.WithCancel(context.Background())
	interval := time.Duration(cfg.StatsUpdateIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	o := &IKEv2{
		config:         ikConfig,
		cfg:            cfg,
		users:          newUserStore(ikConfig.InboundTag),
		vici:           newViciSession(viciSocketPath),
		statsTracker:   stats.New(),
		interfaceStats: stats.NewInterfaceCountersTracker(),
		saSeen:         make(map[uint32][2]int64),
		cumRx:          make(map[string]int64),
		cumTx:          make(map[string]int64),
		waitDone:       make(chan struct{}),
		logChan:        make(chan string, cfg.LogBufferSize),
		cancel:         cancel,
		startTime:      time.Now(),
		updateInterval: interval,
		state:          lifecycleStopped,
	}
	o.users.replaceAll(users)

	if err := o.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return o, nil
}

func (o *IKEv2) start(ctx context.Context) error {
	if err := o.writeConfig(); err != nil {
		return fmt.Errorf("write ikev2 config: %w", err)
	}
	if err := o.setupNAT(); err != nil {
		o.emitLogf("Warning", "ikev2: nat setup failed: %v", err)
	}

	// Supervise charon in the foreground. It uses the default VICI socket.
	cmd := exec.CommandContext(ctx, charonBinary)
	cmd.Env = append(os.Environ(), "STRONGSWAN_CONF=/etc/strongswan.conf")
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	o.process = cmd
	go o.pump(stdout)
	go o.pump(stderr)
	go func() { _ = cmd.Wait(); close(o.waitDone) }()

	if err := o.waitForSocket(15 * time.Second); err != nil {
		return err
	}

	if err := o.reload(); err != nil {
		return fmt.Errorf("swanctl load: %w", err)
	}

	o.mu.Lock()
	o.state = lifecycleRunning
	o.mu.Unlock()

	go o.pollLoop(ctx)
	o.emitLogf("Info", "ikev2: started (%s)", o.config.InboundTag)
	return nil
}

func (o *IKEv2) waitForSocket(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(viciSocketPath); err == nil {
			// Confirm the daemon answers.
			if s, e := o.vici.open(); e == nil {
				s.Close()
				return nil
			}
		}
		select {
		case <-o.waitDone:
			return errors.New("charon exited before the VICI socket was ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("timed out waiting for the charon VICI socket")
}

// reload writes the swanctl config (with the current user secrets) and loads it.
func (o *IKEv2) reload() error {
	if err := o.writeSwanctl(); err != nil {
		return err
	}
	cmd := exec.Command(swanctlBinary, "--load-all", "--noprompt")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (o *IKEv2) pump(r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n") {
				o.emitLog("Info", line)
			}
		}
		if err != nil {
			return
		}
	}
}

// --- Backend interface ---

func (o *IKEv2) Started() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state == lifecycleRunning
}

func (o *IKEv2) Version() string { return DetectVersion() }

func (o *IKEv2) Logs() <-chan string { return o.logChan }

func (o *IKEv2) Restart() error {
	o.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.waitDone = make(chan struct{})
	o.shutdownOnce = sync.Once{}
	return o.start(ctx)
}

func (o *IKEv2) Shutdown() {
	o.shutdownOnce.Do(func() {
		o.mu.Lock()
		o.state = lifecycleStopped
		o.mu.Unlock()
		if o.cancel != nil {
			o.cancel()
		}
		if o.process != nil && o.process.Process != nil {
			_ = o.process.Process.Kill()
		}
		select {
		case <-o.waitDone:
		case <-time.After(5 * time.Second):
		}
		if o.hostRouting != nil {
			o.hostRouting()
		}
		o.emitLog("Info", "ikev2: shutdown complete")
	})
}

func (o *IKEv2) SyncUser(ctx context.Context, user *common.User) error {
	return o.applyUsers([]*common.User{user})
}

func (o *IKEv2) SyncUsers(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.reload()
}

func (o *IKEv2) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(users)
}

func (o *IKEv2) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *IKEv2) applyUsers(users []*common.User) error {
	for _, u := range users {
		o.users.applyUser(u)
	}
	return o.reload()
}

func (o *IKEv2) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
