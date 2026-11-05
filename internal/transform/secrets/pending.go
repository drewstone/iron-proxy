package secrets

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// defaultPendingWait bounds how long a request that carries a pending
// placeholder is held for the real secret to be installed.
const defaultPendingWait = 5 * time.Second

// pendingEntry declares a placeholder whose real secret has not been installed
// yet. A box that boots before its credential is minted carries the
// placeholder in its env; the host installs the secret afterwards by rewriting
// the config (the placeholder gains a secrets entry) and reloading. A request
// that carries the placeholder in that window is held until the install lands
// instead of leaving with the placeholder unswapped.
type pendingEntry struct {
	ProxyValue   string                 `yaml:"proxy_value"`
	MatchHeaders []string               `yaml:"match_headers,omitempty"`
	Rules        []hostmatch.RuleConfig `yaml:"rules"`
	// Name labels the credential in logs (the env var name, never a value).
	Name      string `yaml:"name,omitempty"`
	SandboxID string `yaml:"sandbox_id,omitempty"`
}

type resolvedPending struct {
	slot         *pendingSlot
	proxyValue   string
	matchHeaders []headerMatcher
	rules        []hostmatch.Rule
	name         string
	sandboxID    string
}

// pendingSlot is the rendezvous between a waiting request and the reload that
// installs its secret. Slots outlive pipelines: a reload builds a new Secrets
// transform and the old one is closed, so the install has to be visible across
// the swap. ready closes once, when an entry for the placeholder resolves.
type pendingSlot struct {
	ready    chan struct{}
	resolved *resolvedSecret
}

var pendingSlots = struct {
	sync.Mutex
	byValue map[string]*pendingSlot
}{byValue: map[string]*pendingSlot{}}

// declarePending returns the slot for a placeholder that has no secret yet. A
// placeholder that was installed earlier and is declared pending again starts a
// new wait.
func declarePending(proxyValue string) *pendingSlot {
	pendingSlots.Lock()
	defer pendingSlots.Unlock()
	if slot, ok := pendingSlots.byValue[proxyValue]; ok && slot.resolved == nil {
		return slot
	}
	slot := &pendingSlot{ready: make(chan struct{})}
	pendingSlots.byValue[proxyValue] = slot
	return slot
}

// installPending releases every request waiting on the placeholder.
func installPending(proxyValue string, sec *resolvedSecret) {
	pendingSlots.Lock()
	defer pendingSlots.Unlock()
	slot, ok := pendingSlots.byValue[proxyValue]
	if !ok || slot.resolved != nil {
		return
	}
	slot.resolved = sec
	close(slot.ready)
}

func compilePending(i int, entry pendingEntry) (resolvedPending, error) {
	if entry.ProxyValue == "" {
		return resolvedPending{}, fmt.Errorf("pending[%d]: proxy_value is required", i)
	}
	matchers, err := parseHeaderMatchers(entry.MatchHeaders, fmt.Sprintf("pending[%d]", i))
	if err != nil {
		return resolvedPending{}, err
	}
	rules, err := hostmatch.CompileRules(entry.Rules, fmt.Sprintf("pending[%d]", i))
	if err != nil {
		return resolvedPending{}, err
	}
	return resolvedPending{
		slot:         declarePending(entry.ProxyValue),
		proxyValue:   entry.ProxyValue,
		matchHeaders: matchers,
		rules:        rules,
		name:         entry.Name,
		sandboxID:    entry.SandboxID,
	}, nil
}

// carries reports whether the request holds the placeholder in a header the
// entry scans (every header when none are named).
func (p *resolvedPending) carries(req *http.Request) bool {
	if len(p.matchHeaders) == 0 {
		for name, vals := range req.Header {
			for _, v := range vals {
				if headerContains(name, v, p.proxyValue) {
					return true
				}
			}
		}
		return false
	}
	for _, m := range p.matchHeaders {
		for name, vals := range req.Header {
			if m.re != nil {
				if !m.re.MatchString(name) {
					continue
				}
			} else if http.CanonicalHeaderKey(name) != m.name {
				continue
			}
			for _, v := range vals {
				if headerContains(name, v, p.proxyValue) {
					return true
				}
			}
		}
	}
	return false
}

func pendingUnavailable(req *http.Request, name string) *transform.TransformResult {
	body := fmt.Sprintf("egress credential %q is not installed yet; the request was not sent upstream\n", name)
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 " + http.StatusText(http.StatusServiceUnavailable),
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}, "Retry-After": []string{"2"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		},
	}
}

// waitForPending holds a request that carries a pending placeholder until its
// secret is installed, then swaps it. It fails closed: on timeout, a failed
// read of the installed secret, or a cancelled request, the placeholder never
// leaves. It returns a nil result when no pending placeholder applies.
func (s *Secrets) waitForPending(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	for i := range s.pending {
		p := &s.pending[i]
		if !hostmatch.MatchAnyRule(p.rules, req) || !p.carries(req) {
			continue
		}
		start := time.Now()
		outcome := "installed"
		select {
		case <-p.slot.ready:
		default:
			timer := time.NewTimer(s.pendingWait)
			select {
			case <-p.slot.ready:
			case <-timer.C:
				outcome = "timeout"
			case <-ctx.Done():
				outcome = "canceled"
			}
			timer.Stop()
		}
		waited := time.Since(start)
		var result *transform.TransformResult
		if outcome == "installed" {
			pendingSlots.Lock()
			sec := p.slot.resolved
			pendingSlots.Unlock()
			var locations []string
			var err error
			if sec.presentation != nil {
				locations, err = sec.swapCanonical(ctx, tctx, req)
			} else {
				var value string
				value, err = sec.source.Get(ctx)
				if err == nil {
					locations = s.swapHeaders(req, sec, value)
					rememberScrub(req, sec, value)
				}
			}
			if err != nil {
				outcome = "unavailable"
			} else {
				tctx.Annotate("swapped", []map[string]any{{"secret": sec.source.Name(), "locations": locations}})
			}

		}
		s.logger.Log(ctx, pendingLogLevel(outcome), "egress pending placeholder waited",
			slog.String("sandboxId", p.sandboxID),
			slog.String("secret", p.name),
			slog.Int64("waitedMs", waited.Milliseconds()),
			slog.String("outcome", outcome))
		if outcome != "installed" {
			tctx.Annotate("rejected", p.name)
			tctx.Annotate("reject_reason", "pending_placeholder_"+outcome)
			result = pendingUnavailable(req, p.name)
			return result, nil
		}
	}
	return nil, nil
}

func pendingLogLevel(outcome string) slog.Level {
	if outcome == "installed" {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}
