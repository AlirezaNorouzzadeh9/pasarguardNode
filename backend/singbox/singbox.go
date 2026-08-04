package singbox

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

var errNotStarted = errors.New("singbox not started")

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

// SingBox runs sing-box in-process.
//
// It is embedded as a library rather than supervised as a child process on
// purpose: sing-box exposes no external API for changing an inbound's users
// (only shadowsocks-2022 has one), so the only way to add a user without
// restarting the whole thing is to reach into the running instance and rebuild
// that one inbound — which requires being inside the same process.
type SingBox struct {
	config *Config
	cfg    *config.Config

	mu       sync.RWMutex
	instance *box.Box
	state    lifecycleState
	users    []*common.User

	// runCtx outlives any single RPC. Inbounds rebuilt during a user sync are
	// tied to the context passed to Manager.Create, so handing it a request
	// context makes the new inbound die the moment that RPC returns — the
	// listener comes up and is torn down again in the same instant.
	runCtx context.Context

	logChan      chan string
	cancel       context.CancelFunc
	startTime    time.Time
	shutdownOnce sync.Once

	stats *statsClient
}

// New builds and starts a sing-box instance from the panel's config.
func New(cfg *config.Config, sbConfig *Config, users []*common.User) (*SingBox, error) {
	if sbConfig == nil {
		return nil, errors.New("singbox config must not be nil")
	}

	// Derived from the config context so sing-box's type registry travels with
	// it, and cancelled only on shutdown.
	ctx, cancel := context.WithCancel(sbConfig.Ctx)
	s := &SingBox{
		config:    sbConfig,
		cfg:       cfg,
		logChan:   make(chan string, cfg.LogBufferSize),
		cancel:    cancel,
		startTime: time.Now(),
		state:     lifecycleStopped,
		users:     append([]*common.User(nil), users...),
		runCtx:    ctx,
	}

	if err := s.start(ctx); err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func (s *SingBox) start(ctx context.Context) error {
	opts := s.config.Options

	// Seed every user-bearing inbound with the startup user set, so users work
	// before the panel's first sync rather than only after it.
	inbounds := make([]option.Inbound, 0, len(opts.Inbounds))
	for _, in := range opts.Inbounds {
		if carriesUsers(in) {
			applied, err := applyUsers(in, s.users)
			if err != nil {
				return fmt.Errorf("seed users for inbound %q: %w", in.Tag, err)
			}
			in = applied
		}
		inbounds = append(inbounds, in)
	}
	opts.Inbounds = inbounds

	instance, err := box.New(box.Options{Context: s.config.Ctx, Options: opts})
	if err != nil {
		return fmt.Errorf("build singbox: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return fmt.Errorf("start singbox: %w", err)
	}

	s.mu.Lock()
	s.instance = instance
	s.state = lifecycleRunning
	s.mu.Unlock()

	s.stats = newStatsClient(s.config.APIAddr)

	s.emitLogf("singbox started (%d inbound(s): %v)", len(s.config.InboundTags), s.config.InboundTags)
	log.Printf("singbox started, inbounds: %v, stats api: %s", s.config.InboundTags, s.config.APIAddr)
	return nil
}

func (s *SingBox) Started() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state == lifecycleRunning && s.instance != nil
}

func (s *SingBox) Version() string {
	return constant.Version
}

func (s *SingBox) Logs() <-chan string {
	return s.logChan
}

func (s *SingBox) emitLogf(format string, args ...any) {
	select {
	case s.logChan <- fmt.Sprintf(format, args...):
	default: // never block the caller on a log line
	}
}

// Restart tears the instance down and brings it back with the current users.
func (s *SingBox) Restart() error {
	s.mu.Lock()
	old := s.instance
	s.instance = nil
	s.state = lifecycleStopped
	s.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	ctx, cancel := context.WithCancel(s.config.Ctx)
	s.mu.Lock()
	s.runCtx = ctx
	s.mu.Unlock()
	s.cancel = cancel
	if err := s.start(ctx); err != nil {
		cancel()
		return err
	}
	return nil
}

func (s *SingBox) Shutdown() {
	s.shutdownOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Lock()
		instance := s.instance
		s.instance = nil
		s.state = lifecycleStopped
		s.mu.Unlock()

		if instance != nil {
			_ = instance.Close()
		}
		if s.stats != nil {
			s.stats.close()
		}
		close(s.logChan)
		log.Println("singbox shutdown complete")
	})
}

func (s *SingBox) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	// Latency probing is an xray feature; the composite backend merges empty
	// results from everyone else.
	return &common.LatencyResponse{}, nil
}

// freeLoopbackPort asks the kernel for an unused port on loopback.
func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", apiListenHost+":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
