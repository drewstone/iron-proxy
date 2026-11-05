package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func (p *Proxy) dialPrivate(ctx context.Context, network, address string, req *http.Request) (net.Conn, error) {
	policy := &http.Request{Method: req.Method, URL: &url.URL{Host: req.URL.Host, Path: req.URL.Path, RawPath: req.URL.RawPath}}
	allowed := func(pipeline *transform.Pipeline, address string) bool {
		ip, err := netip.ParseAddrPort(address)
		if err != nil {
			return false
		}
		if !p.guard.IsDenied(ip.Addr()) {
			return true
		}
		permit := pipeline.PrivateIPPermission(policy)
		return permit != nil && permit(ip.Addr().Unmap().WithZone(""))
	}
	dialer := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Resolver: p.resolver,
		Control: func(network, address string, raw syscall.RawConn) error {
			err := p.guard.DialControl(network, address, raw)
			if dnsguard.IsDenyError(err) && allowed(p.pipeline.Load(), address) {
				return nil
			}
			return err
		},
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return conn, err
	}
	tracked, err := p.pipeline.TrackPrivateConnection(conn, func(pipeline *transform.Pipeline) bool { return allowed(pipeline, conn.RemoteAddr().String()) })
	if err != nil {
		_ = conn.Close()
	} // Failed admission must leave no live socket.
	return tracked, err
}

// RoundTrip is the single HTTP/WebSocket send boundary, including replay.
func (p *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := secrets.ValidateFinalDestination(req); err != nil {
		return nil, err
	}
	if p.pipeline.Load().PrivateIPPermission(req) == nil {
		return p.transport.RoundTrip(req)
	}
	if p.transport.Proxy != nil {
		upstream, err := p.transport.Proxy(req)
		if err != nil || upstream != nil {
			return nil, fmt.Errorf("per-domain private IP exceptions require a direct upstream")
		}
	}
	transport := p.transport.Clone()
	transport.Proxy, transport.DialTLS, transport.DialTLSContext = nil, nil, nil
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return p.dialPrivate(ctx, network, address, req)
	}
	return transport.RoundTrip(req)
}
