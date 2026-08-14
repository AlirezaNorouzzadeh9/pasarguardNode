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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	// How long to wait before bringing a crashed core back, and the ceiling the
	// delay grows to. A config sing-box rejects fails identically every time, so
	// retrying tight would only bury the reason in the log.
	restartBackoffMin = 2 * time.Second
	restartBackoffMax = 60 * time.Second
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
	// Set while a shutdown or restart was asked for, so the supervisor can
	// tell an intentional exit from a crash and not fight a deliberate stop.
	stopping bool
	// Whether a restart supervisor is already running. Without it every exit
	// starts another, and since each failed restart produces another exit they
	// accumulate rather than replace one another.
	supervising bool

	// The user set as the panel last described it, and the machinery that
	// turns a stream of individual changes into one push.
	usersMu   sync.Mutex
	users     map[string]userCredentials // email -> the secrets they authenticate with
	pushTimer *time.Timer

	// Which position in the pushed list belongs to which user.
	//
	// sing-box identifies an authenticated client by its index in the list it
	// was last given, and a live session keeps the index it got when it
	// connected. So the position a user occupies is their identity for as long
	// as they stay connected, and it has to survive every later push.
	//
	// Rebuilding the list from the map instead — which is what this used to do
	// — reordered it on every change, because Go randomises map iteration.
	// A session that had authenticated as index 4 then found index 4 belonging
	// to somebody else, and its traffic was billed to that person.
	slots []string // index -> email; "" marks a freed slot

	pushStop chan struct{}
}

// New starts sing-box with the given config and user set.
func New(cfg *config.Config, singboxConfig *Config, users []*common.User) (*SingBox, error) {
	s := &SingBox{
		config:   singboxConfig,
		cfg:      cfg,
		logChan:  make(chan string, logChanSize),
		users:    make(map[string]userCredentials, len(users)),
		pushStop: make(chan struct{}),
		client:   newClashClient(singboxConfig.clashAPIAddress, singboxConfig.clashAPISecret),
		// Built once and kept for the life of the backend, not rebuilt on every
		// start. It holds counters drained from sing-box that the panel has not
		// collected yet, so replacing it on restart lost real usage; and being
		// written only here means the readers in GetStats and teardown are not
		// racing a start that is reassigning it.
		stats: newStatsClient(singboxConfig.statsAddress),
	}
	for _, u := range users {
		if email, creds, ok := s.credentials(u); ok {
			s.users[email] = creds
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

	// Held locally as well as on the struct. The watcher below closes this
	// channel, not s.waitDone: by the time a process exits, a later start may
	// already have put its own channel on the struct, and closing that one
	// leaves it to be closed a second time when that process exits too. A
	// double close panics, and a panic in a goroutine takes the whole node down
	// — xray, WireGuard and OpenVPN with it — for a core that merely failed to
	// come up. Seen on a live node: a sing-box core whose certificate was
	// missing crash-looped the process every two minutes.
	done := make(chan struct{})

	s.mu.Lock()
	s.stopping = false
	s.process = cmd
	s.cancel = cancel
	s.waitDone = done
	s.startTime = time.Now()
	s.mu.Unlock()

	go s.pipeLogs(stdout)
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		s.started = false
		asked := s.stopping
		// Only the supervisor this exit belongs to may be started, and only if
		// none is already running: every failed restart ends in another exit,
		// so spawning one per exit multiplies them until the host is carrying a
		// crowd of goroutines all restarting the same core.
		spawn := !asked && !s.supervising
		if spawn {
			s.supervising = true
		}
		s.mu.Unlock()
		close(done)
		// A core that dies on its own used to stay dead: the node kept reporting
		// itself connected while every user on this core was cut off, and only a
		// manual restart brought it back.
		if spawn {
			go s.superviseRestart()
		}
	}()

	if err := s.waitReady(ctx, done); err != nil {
		// teardown, not Shutdown: this is cleaning up a start that failed, not
		// an operator stopping the core. Shutdown says "stop and stay stopped",
		// which the supervisor reads as its own cue to give up — so using it
		// here made one failed restart the last one ever attempted.
		s.teardown()
		return err
	}

	s.mu.Lock()
	s.started = true
	s.version = s.readVersion()
	s.mu.Unlock()

	return nil
}

// waitReady polls clash_api until it answers. Reporting the backend started
// before that would let the panel mark the node connected while the process is
// still deciding whether its config parses.
//
// It watches the channel belonging to the process it started, passed in rather
// than read off the struct: a restart overlapping this one would have put its
// own there, and waiting on that means waiting for the wrong process to exit.
func (s *SingBox) waitReady(ctx context.Context, done <-chan struct{}) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return errors.New("singbox: process exited before it became ready")
		case <-done:
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

// Shutdown stops the core and keeps it stopped.
//
// The difference from teardown is the intent it records: stopping tells the
// supervisor not to bring the process back, and closing pushStop wakes it out
// of a backoff sleep instead of leaving it to wait out the full delay.
func (s *SingBox) Shutdown() {
	s.mu.Lock()
	s.stopping = true // tells the supervisor this exit was asked for
	if s.pushStop != nil {
		// Set to nil as well as closed, so a second Shutdown does not panic on
		// a channel that is already closed. A nil channel blocks forever, which
		// is the right reading for a supervisor that has nothing to wait for.
		close(s.pushStop)
		s.pushStop = nil
	}
	s.mu.Unlock()

	s.teardown()
}

// teardown stops the process and lets go of what it owned, without saying
// anything about whether it should come back.
func (s *SingBox) teardown() {
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
	// Only the connection is dropped. The counters already read out of sing-box
	// but not yet handed to the panel live on the client, and a restart that
	// replaced it would throw away usage nobody has been billed for yet.
	if s.stats != nil {
		s.stats.close()
	}
}

// superviseRestart brings the core back after it exits on its own.
//
// Backed off rather than retried tight: a config sing-box refuses will fail
// every time, and hammering it turns one broken core into a busy loop that
// buries the reason in the log. The delay grows to a minute and stays there, so
// a core that is down for an external reason — a port taken, a certificate file
// briefly missing — recovers on its own once that clears.
//
// Users are pushed again after each successful start, because the process comes
// up with only whatever the config file carried, which is none of them.
func (s *SingBox) superviseRestart() {
	// Every path out of this loop has to release the flag, or a core that dies
	// again later would find a supervisor still marked as running and never be
	// brought back.
	defer func() {
		s.mu.Lock()
		s.supervising = false
		s.mu.Unlock()
	}()

	delay := restartBackoffMin
	for {
		s.mu.RLock()
		stopping := s.stopping
		stop := s.pushStop
		s.mu.RUnlock()
		if stopping {
			return
		}

		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		s.mu.RLock()
		stopping = s.stopping
		running := s.started
		s.mu.RUnlock()
		if stopping {
			return
		}
		// Restart() stops the core and starts it again itself. A supervisor left
		// over from the stop half would otherwise wake to a core that is already
		// up and start a second process on the same ports, which the first one
		// holds — so it would fail, back off, and keep trying against a core that
		// was never broken.
		if running {
			return
		}

		s.emitLogf("core exited on its own; restarting")
		if err := s.start(); err != nil {
			s.emitLogf("restart failed: %v", err)
			if delay < restartBackoffMax {
				delay *= 2
				if delay > restartBackoffMax {
					delay = restartBackoffMax
				}
			}
			continue
		}
		if err := s.pushUsers(context.Background()); err != nil {
			// The core is up but has nobody in it, which serves no one. Better
			// to fail loudly here than to look healthy and refuse every user.
			s.emitLogf("restarted, but pushing users failed: %v", err)
		}
		s.emitLogf("core restarted")
		return
	}
}

// -------------------------------------------------------------------- users

// SyncUser applies one change. It does not push on its own — see pushSoon.
func (s *SingBox) SyncUser(_ context.Context, user *common.User) error {
	if user == nil {
		return errors.New("singbox: user is nil")
	}
	email, creds, ok := s.credentials(user)

	s.usersMu.Lock()
	if ok {
		s.users[email] = creds
	} else {
		// No usable credential means the user is not on this backend any more —
		// either removed, or no longer entitled to an inbound it serves.
		delete(s.users, user.GetEmail())
	}
	s.usersMu.Unlock()

	s.pushSoon()
	return nil
}

// SyncUsers is the whole user set. Anyone absent from it is gone.
func (s *SingBox) SyncUsers(ctx context.Context, users []*common.User) error {
	return s.replaceUsers(ctx, users)
}

// UpdateUsers is a change to some users, not the whole set — the same contract
// the xray backend keeps, where SyncUsers rebuilds the client map and
// UpdateUsers only adds and removes the accounts it was handed.
//
// This used to replace everything, which meant any partial update emptied the
// core of every user it did not mention. The panel sends one of these when a
// group's inbounds change, in batches, so each batch discarded the one before
// it and the core was left holding only the last few hundred users: every other
// user on the node stopped authenticating, on every protocol at once, with
// nothing logged anywhere.
func (s *SingBox) UpdateUsers(ctx context.Context, users []*common.User) error {
	return s.mergeUsers(ctx, users)
}

// UpdateUsersAndRestart applies the same change without restarting. The whole
// point of the runtime-users patch is that a user change no longer costs every
// live connection, so honouring the "and restart" literally would give back
// exactly what it bought.
func (s *SingBox) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	return s.mergeUsers(ctx, users)
}

// mergeUsers applies a partial update: each user named is added, updated, or
// removed, and everyone not named is left exactly as they were.
func (s *SingBox) mergeUsers(ctx context.Context, users []*common.User) error {
	s.usersMu.Lock()
	for _, u := range users {
		if u == nil {
			continue
		}
		if email, creds, ok := s.credentials(u); ok {
			s.users[email] = creds
			continue
		}
		// Named but no longer usable here: removed, or no longer entitled to an
		// inbound this core serves.
		delete(s.users, strings.TrimSpace(u.GetEmail()))
	}
	if s.pushTimer != nil {
		s.pushTimer.Stop()
		s.pushTimer = nil
	}
	s.usersMu.Unlock()
	return s.pushUsers(ctx)
}

func (s *SingBox) replaceUsers(ctx context.Context, users []*common.User) error {
	next := make(map[string]userCredentials, len(users))
	for _, u := range users {
		if email, creds, ok := s.credentials(u); ok {
			next[email] = creds
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

// reconcileSlotsLocked lays the current user set out over stable positions.
//
// A user keeps the slot they were first given for as long as they exist, and a
// departed user's slot is held open rather than closed up, because closing it
// would shift everyone after it — and every connected session identified by one
// of those positions would start being billed to its new occupant.
//
// A freed slot cannot simply be omitted: the list is positional, so the hole
// has to be filled. It gets an entry whose password is unusable, which keeps
// the arithmetic intact without leaving a credential anyone can authenticate
// with. Trailing holes are trimmed, so a node that loses users does not carry
// dead weight forever.
//
// Caller holds usersMu.
func (s *SingBox) reconcileSlotsLocked() {
	placed := make(map[string]int, len(s.users))
	for index, email := range s.slots {
		if email == "" {
			continue
		}
		if _, still := s.users[email]; still {
			placed[email] = index
			continue
		}
		s.slots[index] = "" // gone; hold the position open
	}

	// New users take the lowest free slot before extending the list, so the
	// list stays as short as the user count allows.
	free := 0
	for email := range s.users {
		if _, done := placed[email]; done {
			continue
		}
		for free < len(s.slots) && s.slots[free] != "" {
			free++
		}
		if free < len(s.slots) {
			s.slots[free] = email
		} else {
			s.slots = append(s.slots, email)
		}
		placed[email] = free
		free++
	}

	for len(s.slots) > 0 && s.slots[len(s.slots)-1] == "" {
		s.slots = s.slots[:len(s.slots)-1]
	}
}

// payloadForLocked renders the slot table as one inbound's user list.
//
// Each inbound gets its own rendering of the same slots, because the secret
// differs per protocol: a vless inbound is sent uuids and a hysteria2 inbound
// passwords. The positions stay identical across inbounds, which is what keeps
// a live session's index meaning the same user everywhere.
//
// A user entitled to this core but without a secret for this particular
// protocol is not dropped — that would shift everyone below them. They hold
// their position with an unusable placeholder, exactly as a freed slot does.
//
// Caller holds usersMu.
func (s *SingBox) payloadForLocked(kind credentialKind) []clashUser {
	payload := make([]clashUser, len(s.slots))
	for index, email := range s.slots {
		secret := ""
		if email != "" {
			secret = s.users[email].secret(kind)
		}
		if secret == "" {
			// Occupies the position without being usable: the name is not a
			// user id the panel can resolve, and the secret is not one this
			// node ever hands out.
			payload[index] = newClashUser(freeSlotName, kind, freeSlotSecret(kind, index))
			continue
		}
		payload[index] = newClashUser(email, kind, secret)
	}
	return payload
}

// A name the panel will never match to a user, so traffic that somehow lands
// here is dropped rather than billed to someone.
const freeSlotName = "-"

// Random per process: a placeholder password must not be predictable, or it
// becomes a credential anyone who reads this source can use.
var slotNonce = newSlotNonce()

func newSlotNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// Never expected; a fixed string here would be a shared password.
		panic("singbox: cannot read random bytes for slot placeholder: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// freeSlotSecret is a secret nobody can present, in the shape the protocol
// expects.
//
// The shape matters. A uuid protocol will not refuse a placeholder that is not
// a uuid — it stores the zero uuid instead, and every placeholder then shares
// one well-known credential that authenticates as whoever holds that slot. So
// uuid inbounds get a derived uuid rather than a string that merely looks
// unusable.
//
// Derived rather than random per call so a slot's placeholder does not change
// on every push, and derived from the per-process nonce so it cannot be
// guessed from this source.
func freeSlotSecret(kind credentialKind, index int) string {
	if !usesUUID(kind) {
		return fmt.Sprintf("pg-unused-slot-%d-%s", index, slotNonce)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("pg-unused-slot-%d-%s", index, slotNonce)))
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

func usesUUID(kind credentialKind) bool {
	return kind == credVLESS || kind == credVMess
}

func (s *SingBox) pushUsers(ctx context.Context) error {
	s.usersMu.Lock()
	s.reconcileSlotsLocked()
	// Inbounds of the same protocol share one rendering; a core with four vless
	// inbounds should not build the same list four times.
	payloads := make(map[credentialKind][]clashUser, len(s.config.inbounds))
	for _, in := range s.config.inbounds {
		if _, done := payloads[in.kind]; !done {
			payloads[in.kind] = s.payloadForLocked(in.kind)
		}
	}
	s.usersMu.Unlock()

	var failures []string
	for _, in := range s.config.inbounds {
		if err := s.client.replaceUsers(ctx, in.tag, payloads[in.kind]); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", in.tag, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

// userCredentials is the secrets a user authenticates with, one per protocol
// this backend can serve.
//
// A user commonly has several. The same person may be entitled to a hysteria2
// inbound and a vless inbound on one core, and those are two different secrets
// — not one secret reachable two ways. Keeping only the hysteria2 one, as this
// backend originally did, left every other protocol with nothing to send.
type userCredentials struct {
	hysteria2   string
	vlessUUID   string
	vmessUUID   string
	trojanPass  string
	shadowsocks string
}

func (c userCredentials) secret(kind credentialKind) string {
	switch kind {
	case credHysteria2:
		return c.hysteria2
	case credVLESS:
		return c.vlessUUID
	case credVMess:
		return c.vmessUUID
	case credTrojan:
		return c.trojanPass
	case credShadowsocks:
		return c.shadowsocks
	}
	return ""
}

func (c userCredentials) empty() bool {
	return c.hysteria2 == "" && c.vlessUUID == "" && c.vmessUUID == "" &&
		c.trojanPass == "" && c.shadowsocks == ""
}

// credentials reports the secrets this user can present, and whether they
// belong on this backend at all. A user with nothing usable simply is not on
// this core — routine on a node running several, not an error.
func (s *SingBox) credentials(u *common.User) (email string, creds userCredentials, ok bool) {
	if u == nil {
		return "", userCredentials{}, false
	}
	email = strings.TrimSpace(u.GetEmail())
	if email == "" {
		return "", userCredentials{}, false
	}
	// A user who is out of data or past their expiry keeps their credentials —
	// the panel does not erase them, it stops listing the inbounds they may
	// use. Checking only for a credential's presence therefore left limited and
	// expired users fully served: not merely finishing an open session, but
	// free to open new ones. Their quota meant nothing on this backend.
	if !s.servesAnyOf(u.GetInbounds()) {
		return "", userCredentials{}, false
	}

	proxies := u.GetProxies()
	creds = userCredentials{
		hysteria2:   strings.TrimSpace(proxies.GetHysteria().GetAuth()),
		vlessUUID:   strings.TrimSpace(proxies.GetVless().GetId()),
		vmessUUID:   strings.TrimSpace(proxies.GetVmess().GetId()),
		trojanPass:  strings.TrimSpace(proxies.GetTrojan().GetPassword()),
		shadowsocks: strings.TrimSpace(proxies.GetShadowsocks().GetPassword()),
	}
	if creds.empty() {
		return "", userCredentials{}, false
	}
	return email, creds, true
}

// servesAnyOf reports whether any of the inbounds the user is entitled to
// belongs to this core.
func (s *SingBox) servesAnyOf(userInbounds []string) bool {
	if len(userInbounds) == 0 {
		return false
	}
	for _, tag := range userInbounds {
		for _, own := range s.config.inbounds {
			if tag == own.tag {
				return true
			}
		}
	}
	return false
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

// clashUser is one entry of an inbound's user list, in sing-box's own shape.
//
// Which field carries the secret depends on the protocol, and the unused one is
// omitted rather than sent empty: sing-box accepts a vless user with a blank
// uuid and stores the zero uuid instead of refusing it.
type clashUser struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

func newClashUser(name string, kind credentialKind, secret string) clashUser {
	if usesUUID(kind) {
		return clashUser{Name: name, UUID: secret}
	}
	return clashUser{Name: name, Password: secret}
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
