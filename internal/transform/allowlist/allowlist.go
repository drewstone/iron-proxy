// Package allowlist implements a default-deny domain and CIDR allowlist transform.
package allowlist

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts, methods,
// and paths against a set of rules.
type Allowlist struct {
	rules []privateRule
	warn  bool
}

type allowlistConfig struct {
	Domains []string               `yaml:"domains"`
	CIDRs   []string               `yaml:"cidrs"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Warn    bool                   `yaml:"warn"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(cfg allowlistConfig) (*Allowlist, error) {
	configs := append([]hostmatch.RuleConfig(nil), cfg.Rules...)
	for _, host := range cfg.Domains {
		if host != "" {
			configs = append(configs, hostmatch.RuleConfig{Host: host})
		}
	}
	for _, cidr := range cfg.CIDRs {
		configs = append(configs, hostmatch.RuleConfig{CIDR: cidr})
	}
	var rules []privateRule
	for _, rule := range configs {
		compiled, err := hostmatch.CompileRules([]hostmatch.RuleConfig{rule}, "allowlist")
		if err != nil {
			return nil, err
		}
		next, err := compilePrivateRule(compiled[0], rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, next)
	}
	return &Allowlist{rules: rules, warn: cfg.Warn}, nil
}

// New creates an Allowlist from domain globs and CIDR strings.
// All methods and paths are allowed. This is the backwards-compatible constructor.
func New(domains []string, cidrs []string) (*Allowlist, error) {
	return newFromConfig(allowlistConfig{Domains: domains, CIDRs: cidrs})
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	allowed := false
	host := hostmatch.StripPort(req.Host)
	authority := tctx.TunnelAdmission || tctx.Tunnel == nil || matchesTunnelAuthority(tctx.Tunnel.Target, req.Host, req.TLS != nil)
	for _, rule := range a.rules {
		if authority && ((tctx.TunnelAdmission && rule.MatchesHost(host)) || (!tctx.TunnelAdmission && rule.matchesHTTP(req, host))) {
			allowed = true
			break
		}
	}
	if allowed {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if a.warn {
		tctx.Annotate("action", "warn")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func matchesTunnelAuthority(target, requestHost string, tls bool) bool {
	targetHost, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	requestPort := "80"
	if tls {
		requestPort = "443"
	}
	if strings.Contains(requestHost, ":") {
		requestHost, requestPort, err = net.SplitHostPort(requestHost)
		if err != nil {
			return false
		}
	}
	return strings.EqualFold(targetHost, requestHost) && targetPort == requestPort
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
