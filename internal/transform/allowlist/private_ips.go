package allowlist

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

type privateRule struct {
	hostmatch.Rule
	privateIPs []netip.Prefix
}

func (r privateRule) matchesHTTP(req *http.Request, host string) bool {
	return (r.Paths == nil || !strings.ContainsAny(req.URL.EscapedPath(), "%\\;")) && r.Matches(host, req.Method, req.URL.Path)
}
func (a *Allowlist) PrivateIPs(req *http.Request) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, rule := range a.rules {
		if !a.warn && rule.matchesHTTP(req, hostmatch.StripPort(req.URL.Host)) {
			prefixes = append(prefixes, rule.privateIPs...)
		}
	}
	return prefixes
}

func compilePrivateRule(compiled hostmatch.Rule, cfg hostmatch.RuleConfig) (privateRule, error) {
	rule := privateRule{Rule: compiled}
	for _, raw := range cfg.AllowPrivateIPs {
		ip, err := netip.ParsePrefix(raw)
		if err != nil || cfg.Host == "" {
			return privateRule{}, fmt.Errorf("allowlist: invalid per-host private CIDR %q", raw)
		}
		ip = ip.Masked()
		if ip.Addr().Is4In6() {
			ip = netip.PrefixFrom(ip.Addr().Unmap(), ip.Bits()-96)
		}
		rule.privateIPs = append(rule.privateIPs, ip)
	}
	return rule, nil
}
