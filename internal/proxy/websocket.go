package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// Relay decoded messages through the same request-local response mask as HTTP.
// The protocol implementation preserves fragmentation, compression and control frames.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, clientRequest *http.Request, scheme, host string, pl *transform.Pipeline, tctx *transform.TransformContext, result *transform.PipelineResult) {
	target := *r.URL
	target.Host, target.Scheme = host, "ws"
	if scheme == "https" {
		target.Scheme = "wss"
	}
	outgoing := r.Clone(r.Context())
	outgoing.URL, outgoing.Host, outgoing.Method = &target, host, http.MethodGet
	if err := secrets.ValidateFinalDestination(outgoing); err != nil {
		result.Action, result.StatusCode = transform.ActionReject, http.StatusForbidden
		http.Error(w, "credential destination refused", http.StatusForbidden)
		return
	}
	headers := r.Header.Clone()
	sanitizeUpstreamHeaders(headers)
	protocols := offeredProtocols(headers)
	originalProtocols := offeredProtocols(clientRequest.Header)
	for _, name := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		headers.Del(name)
	}
	upstream, response, err := websocket.Dial(r.Context(), target.String(), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: p, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, HTTPHeader: headers, Host: host, Subprotocols: protocols, CompressionMode: websocket.CompressionContextTakeover,
	})
	if response == nil {
		result.StatusCode = http.StatusBadGateway
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err != nil {
		if response.Body != nil {
			defer response.Body.Close()
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			result.StatusCode = http.StatusBadGateway
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
	}
	result.StatusCode = response.StatusCode
	if err == nil {
		defer upstream.CloseNow()
		response.Body = http.NoBody
	}
	response.Body = transform.NewBufferedBody(response.Body, pl.BodyLimits().MaxResponseBodyBytes)
	masked, maskErr := pl.ProcessResponse(r.Context(), tctx, r, response, &result.ResponseTransforms)
	if maskErr != nil {
		if upstream != nil {
			upstream.CloseNow()
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err != nil {
		p.writeResponse(w, masked)
		return
	}
	if masked.StatusCode != http.StatusSwitchingProtocols {
		p.writeResponse(w, masked)
		return
	}
	for key, values := range masked.Header {
		switch http.CanonicalHeaderKey(key) {
		case "Connection", "Upgrade", "Sec-Websocket-Accept", "Sec-Websocket-Protocol", "Sec-Websocket-Extensions":
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	var selected []string
	for index, protocol := range protocols {
		if protocol != upstream.Subprotocol() {
			continue
		}
		if len(originalProtocols) == len(protocols) {
			selected = []string{originalProtocols[index]}
		} else if len(originalProtocols) == 1 {
			selected = originalProtocols
		}
		break
	}
	client, err := websocket.Accept(w, clientRequest, &websocket.AcceptOptions{Subprotocols: selected, InsecureSkipVerify: true, CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		return
	}
	defer client.CloseNow()
	upstream.SetReadLimit(-1)
	client.SetReadLimit(-1)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var once sync.Once
	finish := func() { once.Do(func() { cancel(); client.CloseNow(); upstream.CloseNow() }) }
	// Shutdown ends the relay too; a hijacked connection outlives the server shutdown.
	defer context.AfterFunc(p.shutdownCtx, finish)()
	relay := func(dst, src *websocket.Conn, mask bool) {
		defer finish()
		for {
			kind, reader, err := src.Reader(ctx)
			if err != nil {
				var closed websocket.CloseError
				if errors.As(err, &closed) {
					reason := closed.Reason
					if mask {
						reason = secrets.MaskResponseText(r, reason)
					}
					for len(reason) > 123 {
						_, size := utf8.DecodeLastRuneInString(reason)
						reason = reason[:len(reason)-size]
					}
					_ = dst.Close(closed.Code, reason)
				}
				return
			}
			writer, err := dst.Writer(ctx, kind)
			if err != nil {
				return
			}
			if mask {
				reader = secrets.MaskResponseReader(r, reader)
			}
			_, copyErr := io.Copy(writer, reader)
			closeErr := writer.Close()
			if copyErr != nil || closeErr != nil {
				return
			}
		}
	}
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); relay(upstream, client, false) }()
	relay(client, upstream, true)
	group.Wait()
}

func offeredProtocols(header http.Header) []string {
	var protocols []string
	for _, field := range header.Values("Sec-WebSocket-Protocol") {
		for _, value := range strings.Split(field, ",") {
			if value = strings.TrimSpace(value); value != "" {
				protocols = append(protocols, value)
			}
		}
	}
	return protocols
}
