package singbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// apiListenHost keeps the stats API on loopback: it is an unauthenticated gRPC
// service, and the node talks to it from inside its own process.
const apiListenHost = "127.0.0.1"

// Config is the sing-box configuration the panel ships, already parsed.
//
// The panel sends raw sing-box JSON, the same way it sends raw xray JSON, so a
// new sing-box protocol needs no code here — only a core config in the panel.
type Config struct {
	// Options is the parsed configuration, kept so inbounds can be rebuilt
	// with a new user list without re-parsing the whole document.
	Options option.Options

	// Ctx carries sing-box's type registry; parsing and rebuilding inbounds
	// both need it, so it is created once and reused.
	Ctx context.Context

	// InboundTags lists the tags that carry users, in configuration order.
	InboundTags []string

	// APIAddr is where the V2Ray-compatible stats service listens.
	APIAddr string
}

// NewConfig parses and validates the panel's sing-box configuration.
func NewConfig(configStr string) (*Config, error) {
	if strings.TrimSpace(configStr) == "" {
		return nil, errors.New("singbox config must not be empty")
	}

	// The registry of inbound/outbound types lives in the context, so it has to
	// exist before the document is unmarshalled — without it sing-box reports
	// "missing inbound fields registry in context".
	ctx := include.Context(context.Background())

	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configStr))
	if err != nil {
		return nil, fmt.Errorf("parse singbox config: %w", err)
	}

	if len(opts.Inbounds) == 0 {
		return nil, errors.New("singbox config declares no inbounds")
	}

	tags := make([]string, 0, len(opts.Inbounds))
	seen := make(map[string]struct{}, len(opts.Inbounds))
	for i := range opts.Inbounds {
		tag := strings.TrimSpace(opts.Inbounds[i].Tag)
		if tag == "" {
			return nil, fmt.Errorf("inbound %d has no tag; the panel keys users and hosts on it", i)
		}
		if _, dup := seen[tag]; dup {
			return nil, fmt.Errorf("duplicate inbound tag %q", tag)
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}

	cfg := &Config{Options: opts, Ctx: ctx, InboundTags: tags}
	if err := cfg.ensureStatsAPI(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ensureStatsAPI turns on the V2Ray-compatible stats service, which is how
// per-user traffic gets back to the panel. A config that already declares one
// is respected; otherwise a loopback listener on a free port is added.
func (c *Config) ensureStatsAPI() error {
	if c.Options.Experimental == nil {
		c.Options.Experimental = &option.ExperimentalOptions{}
	}
	if c.Options.Experimental.V2RayAPI == nil {
		c.Options.Experimental.V2RayAPI = &option.V2RayAPIOptions{}
	}
	api := c.Options.Experimental.V2RayAPI

	if strings.TrimSpace(api.Listen) == "" {
		port, err := freeLoopbackPort()
		if err != nil {
			return fmt.Errorf("allocate stats api port: %w", err)
		}
		api.Listen = fmt.Sprintf("%s:%d", apiListenHost, port)
	}
	if api.Stats == nil {
		api.Stats = &option.V2RayStatsServiceOptions{}
	}
	api.Stats.Enabled = true

	// Counters exist only for the inbounds we ask for; users are added as they
	// are synced, so only the inbound list is seeded here.
	api.Stats.Inbounds = append(api.Stats.Inbounds[:0:0], c.InboundTags...)

	addrPort, err := netip.ParseAddrPort(api.Listen)
	if err != nil {
		return fmt.Errorf("stats api listen %q: %w", api.Listen, err)
	}
	c.APIAddr = addrPort.String()
	return nil
}

// InboundOptions returns the configured options for a tag, so it can be rebuilt
// with a different user list.
func (c *Config) InboundOptions(tag string) (option.Inbound, bool) {
	for _, in := range c.Options.Inbounds {
		if in.Tag == tag {
			return in, true
		}
	}
	return option.Inbound{}, false
}
