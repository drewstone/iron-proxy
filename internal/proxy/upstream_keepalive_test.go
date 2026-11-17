package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// silentDropEdge stands in for a Cloudflare edge that drops a connection's
// state without telling the client: after forgetAfter of silence it stops
// forwarding, sends nothing, and answers the client's next bytes with a TCP
// reset. The client's kernel keepalive probes carry no data, so only a probe
// at the HTTP layer can find the dead connection before a request does.
type silentDropEdge struct {
	addr     string
	accepted atomic.Int32
	resets   atomic.Int32
}

func startSilentDropEdge(t *testing.T, upstreamAddr string, forgetAfter time.Duration) *silentDropEdge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	e := &silentDropEdge{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed at cleanup
			}
			e.accepted.Add(1)
			go e.serve(c.(*net.TCPConn), upstreamAddr, forgetAfter)
		}
	}()
	return e
}

func (e *silentDropEdge) serve(client *net.TCPConn, upstreamAddr string, forgetAfter time.Duration) {
	defer func() { _ = client.Close() }() // a refused dial surfaces as the proxy's 502
	up, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }() // also closed when the edge forgets
	done := make(chan struct{})
	defer close(done)

	var last atomic.Int64
	var forgotten atomic.Bool
	last.Store(time.Now().UnixNano())
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := up.Read(buf)
			if n > 0 && !forgotten.Load() {
				last.Store(time.Now().UnixNano())
				if _, err := client.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				if time.Since(time.Unix(0, last.Load())) > forgetAfter {
					forgotten.Store(true)
					_ = up.Close() // the edge's own upstream side; the client hears nothing
					return
				}
			}
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := client.Read(buf)
		if n > 0 {
			if forgotten.Load() {
				e.resets.Add(1)
				_ = client.SetLinger(0) // the deferred Close now sends RST
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := up.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestUpstreamPOSTAfterEdgeDroppedPooledConnection reproduces the us1 502s:
// a POST reuses a pooled HTTP/2 upstream connection whose state the edge
// already dropped, and the edge resets it. The proxy keeps its production
// upstream transport; the test only points its dial at the local edge.
func TestUpstreamPOSTAfterEdgeDroppedPooledConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	var protoMajor atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoMajor.Store(int32(r.ProtoMajor))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body) // the client reads and checks the echo
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	edge := startSilentDropEdge(t, upstream.Listener.Addr().String(), time.Second)

	const host = "router.example.com"
	ca := newIntegrationCA(t)
	al, err := allowlist.New([]string{host}, nil)
	require.NoError(t, err)
	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		CertCache: ca.certCache,
		Pipeline:  transform.NewPipelineHolder(transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)),
		Logger:    logger,
	})
	p.transport.TLSClientConfig.InsecureSkipVerify = true // the local upstream's certificate names no test host
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, edge.addr)
	}
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpsServer.Serve(tls.NewListener(httpsLn, p.httpsServer.TLSConfig)) }()
	t.Cleanup(func() { _ = p.httpsServer.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: ca.caPool, ServerName: host},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, httpsLn.Addr().String())
		},
	}}
	post := func(body string) (int, string) {
		resp, err := client.Post("https://"+host+"/v1/responses", "application/json", strings.NewReader(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(got)
	}

	status, got := post(`{"n":1}`)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, `{"n":1}`, got)
	require.Equal(t, int32(2), protoMajor.Load(), "the upstream leg must be HTTP/2, as Cloudflare serves it")

	// Idle past the edge's forget time and past the proxy's upstream
	// health-check ping, but well inside the 90 s idle-connection timeout.
	time.Sleep(8 * time.Second)

	status, got = post(`{"n":2}`)
	require.Equal(t, http.StatusOK, status, "a POST must not meet a connection the edge already dropped")
	require.Equal(t, `{"n":2}`, got)
	require.Equal(t, int32(1), edge.resets.Load(), "the health-check ping, not the POST, finds the dropped connection")
	require.Equal(t, int32(2), edge.accepted.Load(), "the second POST dials a fresh upstream connection")
}
