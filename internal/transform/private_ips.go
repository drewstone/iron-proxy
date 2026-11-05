package transform

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
)

// Each rejecting allowlist must explicitly authorize the resolved address.
func (p *Pipeline) PrivateIPPermission(req *http.Request) func(netip.Addr) bool {
	var checks [][]netip.Prefix
	for _, candidate := range p.transforms {
		if policy, ok := candidate.(interface {
			PrivateIPs(*http.Request) []netip.Prefix
		}); ok {
			prefixes := policy.PrivateIPs(req)
			if len(prefixes) == 0 {
				return nil
			}
			checks = append(checks, prefixes)
		}
	}
	if len(checks) == 0 {
		return nil
	}
	return func(ip netip.Addr) bool {
		for _, prefixes := range checks {
			if !slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(ip) }) {
				return false
			}
		}
		return true
	}
}

// Reload fences revoked sockets before ACK; unchanged authorization retains them.
func (h *PipelineHolder) Store(next *Pipeline) {
	h.mu.Lock()
	old := h.p.Swap(next)
	for conn := range h.connections {
		if next == nil || !conn.allowed(next) {
			delete(h.connections, conn)
			_ = conn.Conn.Close()
		}
	}
	h.mu.Unlock()
	if old != nil && old != next {
		_ = old.Close()
	} // Existing best-effort transform cleanup.
}

func (h *PipelineHolder) TrackPrivateConnection(conn net.Conn, allowed func(*Pipeline) bool) (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current := h.Load(); current == nil || !allowed(current) {
		return nil, fmt.Errorf("private IP policy was withdrawn")
	}
	tracked := &privateConnection{Conn: conn, holder: h, allowed: allowed}
	if h.connections == nil {
		h.connections = make(map[*privateConnection]struct{})
	}
	h.connections[tracked] = struct{}{}
	return tracked, nil
}

type privateConnection struct {
	net.Conn
	holder  *PipelineHolder
	allowed func(*Pipeline) bool
}

func (c *privateConnection) Close() error {
	c.holder.mu.Lock()
	delete(c.holder.connections, c)
	c.holder.mu.Unlock()
	return c.Conn.Close()
}
