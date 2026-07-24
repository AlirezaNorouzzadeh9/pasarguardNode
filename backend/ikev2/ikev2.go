package ikev2

import (
	"context"
	"errors"
	"fmt"
	"log"
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

// swanctl --version prints "strongSwan swanctl 5.9.5", so match the first
// dotted version anywhere in the output (works without charon running).
var strongswanVersionRe = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)

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
	// onlineIPs is the last poll's snapshot of distinct client IPs per identity
	// (identity -> ip -> last-seen unix ts), used for online reporting and the
	// distinct-IP device limit.
	onlineIPs map[string]map[string]int64

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
		onlineIPs:      make(map[string]map[string]int64),
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
	// Replace the shared core config's certificate with this node's own one
	// when PG_NODE_IKEV2_DOMAIN is set (see autocert.go).
	if err := o.applyAutoCert(); err != nil {
		return fmt.Errorf("ikev2 certificate: %w", err)
	}
	if err := o.writeConfig(); err != nil {
		return fmt.Errorf("write ikev2 config: %w", err)
	}
	go o.watchAutoCert(ctx)
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
	removed := o.users.replaceAll(users)
	err := o.reload()
	o.revokeUsers(removed)
	return err
}

func (o *IKEv2) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(users)
}

func (o *IKEv2) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	o.users.replaceAll(users)
	return o.Restart()
}

func (o *IKEv2) applyUsers(users []*common.User) error {
	var removed []string
	for _, u := range users {
		username, _, wasRemoved := o.users.applyUser(u)
		if wasRemoved && username != "" {
			removed = append(removed, username)
		}
	}
	err := o.reload()
	o.revokeUsers(removed)
	return err
}

// eapSecretID is the unique name swanctl knows a user's EAP secret by. It must
// match the section name writeSwanctl emits ("eap-<username>"), because that is
// what --load-creds registers the secret under and therefore what unload-shared
// needs to remove it again.
func eapSecretID(username string) string { return "eap-" + username }

// revokeUsers cuts off users that are no longer authorized (expired, limited,
// disabled, deleted).
//
// Rewriting swanctl.conf and reloading is NOT enough on its own:
//
//   - An established IKE SA rekeys without re-running EAP, so a user whose
//     credential is gone keeps their tunnel — and keeps burning traffic — until
//     they disconnect by themselves or charon restarts. The config says they're
//     gone while the packets keep flowing.
//   - `swanctl --load-all` has no --clear, so a stale EAP secret can survive the
//     reload and let a revoked user authenticate all over again.
//
// So terminate their live SAs and unload the secret explicitly. Both are
// best-effort: a failure here must not fail the sync, since the config is
// already correct and the next poll will retry.
func (o *IKEv2) revokeUsers(usernames []string) {
	if len(usernames) == 0 || o.vici == nil {
		return
	}

	gone := make(map[string]struct{}, len(usernames))
	for _, u := range usernames {
		if u != "" {
			gone[u] = struct{}{}
		}
	}
	if len(gone) == 0 {
		return
	}

	// Drop the credential so the user can't simply authenticate again.
	for username := range gone {
		if err := o.vici.unloadShared(eapSecretID(username)); err != nil {
			log.Printf("ikev2: unloading EAP secret for %q failed: %v", username, err)
		}
	}

	// Tear down whatever they still have open.
	sas, err := o.vici.listSAs()
	if err != nil {
		log.Printf("ikev2: listing SAs to revoke %v failed: %v", usernames, err)
		return
	}
	for _, sa := range sas {
		if _, ok := gone[sa.Identity]; !ok {
			continue
		}
		if err := o.vici.terminateIKE(sa.IKEID); err != nil {
			log.Printf("ikev2: terminating SA %d for revoked user %q failed: %v", sa.IKEID, sa.Identity, err)
			continue
		}
		o.emitLogf("Info", "ikev2: user %s revoked, terminated SA %d from %s", sa.Identity, sa.IKEID, sa.Remote)
	}
}

func (o *IKEv2) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}
