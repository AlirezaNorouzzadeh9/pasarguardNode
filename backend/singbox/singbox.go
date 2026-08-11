// Package singbox runs sing-box as a node backend.
//
// It is closest in shape to the xray backend — an external process driven over
// an API — but differs in one way that decides the whole design: xray adds and
// removes users one at a time, while sing-box replaces an inbound's entire user
// set in a single call. With a few thousand users that is a large payload, so
// individual changes are collected briefly and pushed once rather than each
// triggering a full replacement.
//
// It also speaks two protocols. Users go over HTTP on clash_api; usage comes
// back over gRPC on v2ray_api.
package singbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

const (
	// How long changes are collected before one full push. Long enough that a
	// burst of edits becomes a single call, short enough that a new user is
	// usable almost immediately.
	pushDebounce = 2 * time.Second

	// The process is given this long to answer on clash_api before Start gives
	// up. A config error kills sing-box within a second or two, so waiting
	// longer only delays a failure that has already happened.
	readyTimeout = 20 * time.Second

	logChanSize = 256
)

// executablePath is where the node looks for sing-box. Overridable for tests.
var executablePath = "sing-box"

type SingBox struct {
	config *Config
	cfg    *config.Config

	process   *exec.Cmd
	cancel    context.CancelFunc
	waitDone  chan struct{}
	logChan   chan string
	configDir string
	version   string
	startTime time.Time

	client *clashClient
	stats  *statsClient

	mu      sync.RWMutex
	started bool

	// The user set as the panel last described it, and the machinery that
	// turns a stream of individual changes into one push.
	usersMu   sync.Mutex
	users     map[string]string // email -> hysteria2 auth password
	pushTimer *time.Timer
	pushStop  chan struct{}
}

// New starts sing-box with the given config and user set.
func New(cfg *config.Config, singboxConfig *Config, users []*common.User) (*SingBox, error) {
	s := &SingBox{
		config:   singboxConfig,
		cfg:      cfg,
		logChan:  make(chan string, logChanSize),
		users:    make(map[string]string, len(users)),
		pushStop: make(chan struct{}),
		client:   newClashClient(singboxConfig.clashAPIAddress, singboxConfig.clashAPISecret),
	}
	for _, u := range users {
		if email, auth, ok := hysteriaCredential(u); ok {
			s.users[email] = auth
		}
	}

	if err := s.start(); err != nil {
		return nil, err
	}
	// Users are pushed after the process answers rather than baked into the
	// config file: it is the same path every later change takes, so if it is
	// broken it is broken immediately and visibly, not only once someone edits
	// a user.
	if err := s.pushUsers(context.Background()); err != nil {
		s.Shutdown()
		return nil, fmt.Errorf("singbox: initial user push failed: %w", err)
	}
	return s, nil
}

// ---------------------------------------------------------------- lifecycle

func (s *SingBox) start() error {
	dir := s.cfg.GeneratedConfigPath
	if dir == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "singbox", sanitise(s.config.InstanceID()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("singbox: create config dir: %w", err)
	}
	configPath := filepath.Join(dir, "config.json")
	// 0600: the config carries the clash_api secret and the TLS key path.
	if err := os.WriteFile(configPath, []byte(s.config.String()), 0o600); err != nil {
		return fmt.Errorf("singbox: write config: %w", err)
	}
	s.configDir = dir

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, executablePath, "run", "-c", configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("singbox: stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("singbox: start process: %w", err)
	}

	s.mu.Lock()
	s.process = cmd
	s.cancel = cancel
	s.waitDone = make(chan struct{})
	s.startTime = time.Now()
	s.mu.Unlock()

	go s.pipeLogs(stdout)
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		s.started = false
		close(s.waitDone)
		s.mu.Unlock()
	}()

	if err := s.waitReady(ctx); err != nil {
		s.Shutdown()
		return err
	}

	s.mu.Lock()
	s.started = true
	s.version = s.readVersion()
	s.mu.Unlock()

	s.stats = newStatsClient(s.config.statsAddress)
	return nil
}

// waitReady polls clash_api until it answers. Reporting the backend started
// before that would let the panel mark the node connected while the process is
// still deciding whether its config parses.
func (s *SingBox) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return errors.New("singbox: process exited before it became ready")
		case <-s.waitDone:
			return errors.New("singbox: process exited before it became ready; check the core log")
		case <-time.After(200 * time.Millisecond):
		}
		if s.client.ping(ctx) == nil {
			return nil
		}
	}
	return fmt.Errorf("singbox: clash_api did not answer within %s", readyTimeout)
}

func (s *SingBox) readVersion() string {
	out, err := exec.Command(executablePath, "version").Output()
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return ""
}

func (s *SingBox) pipeLogs(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case s.logChan <- scanner.Text():
		default:
			// Dropping is deliberate: a log consumer that stopped reading must
			// not be able to block the process it is reading from.
		}
	}
}

func (s *SingBox) Started() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

func (s *SingBox) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *SingBox) Logs() <-chan string { return s.logChan }

func (s *SingBox) Restart() error {
	s.Shutdown()
	s.mu.Lock()
	s.pushStop = make(chan struct{})
	s.mu.Unlock()
	if err := s.start(); err != nil {
		return err
	}
	return s.pushUsers(context.Background())
}

func (s *SingBox) Shutdown() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.waitDone
	s.cancel = nil
	s.started = false
	s.mu.Unlock()

	s.usersMu.Lock()
	if s.pushTimer != nil {
		s.pushTimer.Stop()
		s.pushTimer = nil
	}
	s.usersMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
	if s.stats != nil {
		s.stats.close()
	}
}

// -------------------------------------------------------------------- users

// SyncUser applies one change. It does not push on its own — see pushSoon.
func (s *SingBox) SyncUser(_ context.Context, user *common.User) error {
	if user == nil {
		return errors.New("singbox: user is nil")
	}
	email, auth, ok := hysteriaCredential(user)

	s.usersMu.Lock()
	if ok {
		s.users[email] = auth
	} else {
		// No hysteria2 credential means the user is not on this backend any
		// more — either removed, or their protocol changed.
		delete(s.users, user.GetEmail())
	}
	s.usersMu.Unlock()

	s.pushSoon()
	return nil
}

func (s *SingBox) SyncUsers(ctx context.Context, users []*common.User) error {
	return s.replaceUsers(ctx, users)
}

func (s *SingBox) UpdateUsers(ctx context.Context, users []*common.User) error {
	return s.replaceUsers(ctx, users)
}

// UpdateUsersAndRestart replaces the user set without restarting. The whole
// point of the runtime-users patch is that a user change no longer costs every
// live connection, so honouring the "and restart" literally would give back
// exactly what it bought.
func (s *SingBox) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	return s.replaceUsers(ctx, users)
}

func (s *SingBox) replaceUsers(ctx context.Context, users []*common.User) error {
	next := make(map[string]string, len(users))
	for _, u := range users {
		if email, auth, ok := hysteriaCredential(u); ok {
			next[email] = auth
		}
	}
	s.usersMu.Lock()
	s.users = next
	if s.pushTimer != nil {
		s.pushTimer.Stop()
		s.pushTimer = nil
	}
	s.usersMu.Unlock()
	return s.pushUsers(ctx)
}

// pushSoon collects changes into one push. Each inbound's user list is replaced
// whole, so ten edits in a row would otherwise mean ten full uploads of every
// user on the node.
func (s *SingBox) pushSoon() {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if s.pushTimer != nil {
		s.pushTimer.Reset(pushDebounce)
		return
	}
	s.pushTimer = time.AfterFunc(pushDebounce, func() {
		s.usersMu.Lock()
		s.pushTimer = nil
		s.usersMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.pushUsers(ctx); err != nil {
			s.emitLogf("failed to push users: %v", err)
		}
	})
}

func (s *SingBox) pushUsers(ctx context.Context) error {
	s.usersMu.Lock()
	payload := make([]clashUser, 0, len(s.users))
	for email, auth := range s.users {
		payload = append(payload, clashUser{Name: email, Password: auth})
	}
	s.usersMu.Unlock()

	var failures []string
	for _, tag := range s.config.inboundTags {
		if err := s.client.replaceUsers(ctx, tag, payload); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", tag, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

// hysteriaCredential reports the user's hysteria2 auth, and whether they have
// one at all. A user with no hysteria2 proxy simply does not belong to this
// backend — that is routine on a node running several cores, not an error.
func hysteriaCredential(u *common.User) (email string, auth string, ok bool) {
	if u == nil {
		return "", "", false
	}
	email = strings.TrimSpace(u.GetEmail())
	auth = strings.TrimSpace(u.GetProxies().GetHysteria().GetAuth())
	if email == "" || auth == "" {
		return "", "", false
	}
	return email, auth, true
}

func (s *SingBox) emitLogf(format string, args ...any) {
	select {
	case s.logChan <- fmt.Sprintf("[singbox] "+format, args...):
	default:
	}
}

func sanitise(name string) string {
	if name == "" {
		return "default"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}

// ------------------------------------------------------------------ clash_api

type clashUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type clashClient struct {
	base   string
	secret string
	http   *http.Client
}

func newClashClient(address, secret string) *clashClient {
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	return &clashClient{
		base:   strings.TrimRight(address, "/"),
		secret: secret,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *clashClient) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/version", nil)
	if err != nil {
		return err
	}
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clash_api returned %d", resp.StatusCode)
	}
	return nil
}

// replaceUsers swaps an inbound's entire user set. sing-box has no incremental
// add or remove; this is the only shape available.
func (c *clashClient) replaceUsers(ctx context.Context, tag string, users []clashUser) error {
	body, err := json.Marshal(map[string]any{"users": users})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPut, c.base+"/inbounds/"+tag+"/users", bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clash_api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

func (c *clashClient) auth(req *http.Request) {
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
}
