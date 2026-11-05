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
	rules []hostmatch.Rule
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
	var rules []hostmatch.Rule

	// Flat domains → rules with no method/path restrictions.
	for _, d := range cfg.Domains {
		m, err := hostmatch.New([]string{d}, nil)
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Flat CIDRs → rules with no method/path restrictions.
	for _, c := range cfg.CIDRs {
		m, err := hostmatch.New(nil, []string{c})
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Explicit rules with optional method/path restrictions.
	compiled, err := hostmatch.CompileRules(cfg.Rules, "allowlist")
	if err != nil {
		return nil, err
	}
	rules = append(rules, compiled...)

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
	if tctx.TunnelAdmission {
		// A CONNECT has no inner method or path. Admit the tunnel by host,
		// then check each parsed HTTP request against the full rule.
		host := hostmatch.StripPort(req.Host)
		for i := range a.rules {
			if a.rules[i].MatchesHost(host) {
				allowed = true
				break
			}
		}
	} else {
		host := hostmatch.StripPort(req.Host)
		// Reject escaped and path-parameter forms for scoped rules. An upstream
		// can decode or strip them again after the proxy checks the URL path.
		ambiguousPath := strings.ContainsAny(req.URL.EscapedPath(), "%\\;")
		tunnelAuthorityMatches := tctx.Tunnel == nil || matchesTunnelAuthority(tctx.Tunnel.Target, req.Host, req.TLS != nil)
		for i := range a.rules {
			rule := &a.rules[i]
			if !tunnelAuthorityMatches {
				continue
			}
			if rule.Paths != nil && ambiguousPath {
				continue
			}
			if rule.Matches(host, req.Method, req.URL.Path) {
				allowed = true
				break
			}
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
