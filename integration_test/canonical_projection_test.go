package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/cagen"
)

// The canonical secret is redeemed for an exact HTTPS host, so the fixture
// serves that host over real TLS: the client reaches the proxy's MITM
// listener with the host's SNI, and the proxy reaches the upstream through a
// CONNECT tunnel (HTTPS_PROXY) that trusts only the upstream's own
// certificate (SSL_CERT_FILE). The peer is in canonical_projection_peer_test.go.
const (
	projectionHost        = "api.reflect.test"
	projectionPlaceholder = "proxy-native-placeholder-0001"
	digitsPlaceholder     = "900000000000000000000000000001"
	wordPlaceholder       = "digits-word-placeholder"
	publicEvents          = ": keepalive\n\nevent: delta\ndata: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\ndata: plain text\n\n"
)

var (
	projectionBearer = map[string]string{"Authorization": "Bearer " + projectionPlaceholder}
	numberHeader     = map[string]string{"X-Digits-Number": digitsPlaceholder}
	wordHeader       = map[string]string{"X-Digits-Word": wordPlaceholder}
)

// projectionFixture is one declared host over real TLS, its CONNECT tunnel
// and the built proxy binary, with the source values it was given.
type projectionFixture struct {
	r1, r2, digits, sourcePath string
	peer                       *projectionPeer
	client                     *http.Client
	releaseHeld                func()
}

func (f *projectionFixture) send(path string, credential map[string]string) (*http.Response, error) {
	return projectionSend(f.client, path, credential)
}

func newProjectionFixture(t *testing.T) *projectionFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := cagen.Generate(cagen.Options{Name: "projection test CA", ExpiryHours: 1, Algorithm: cagen.Ed25519})
	require.NoError(t, err)
	caCert, caKey, err := cagen.WriteFiles(filepath.Join(dir, "ca"), ca)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.CertPEM))

	r1, r2, digits := projectionSecret(t), projectionSecret(t), digitsSecret(t)
	sourcePath, digitsPath := filepath.Join(dir, "source"), filepath.Join(dir, "digits")
	writeSource(t, sourcePath, r1)
	writeSource(t, digitsPath, digits)
	peer := &projectionPeer{current: &atomic.Pointer[string]{}, digits: digits, release: make(chan struct{}), blob: make([]byte, 64<<10), closed: make(chan bool, 2)}
	peer.current.Store(&r1)
	_, err = rand.Read(peer.blob)
	require.NoError(t, err)

	cert, certPath := projectionUpstreamCert(t, dir)
	upstream := httptest.NewUnstartedServer(peer)
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	// Runs before upstream.Close, so a failed case never leaves the held
	// handler waiting.
	releaseHeld := sync.OnceFunc(func() { close(peer.release) })
	t.Cleanup(releaseHeld)
	tunnel := connectTunnel(t, upstream.Listener.Addr().String())

	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cfgPath := renderConfig(t, dir, "canonical_projection.yaml", map[string]string{
		"CACert": caCert, "CAKey": caKey, "Host": projectionHost, "ExpiresAt": expires,
		"SourcePath": sourcePath, "Placeholder": projectionPlaceholder,
		"DigitsPath": digitsPath, "DigitsPlaceholder": digitsPlaceholder, "WordPlaceholder": wordPlaceholder,
	})
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{
		"HTTPS_PROXY=http://" + tunnel, "https_proxy=", "NO_PROXY=", "no_proxy=",
		"SSL_CERT_FILE=" + certPath,
	})
	httpsAddr := proxy.AddrFor(t, "https proxy starting")
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, httpsAddr)
		},
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	t.Cleanup(func() { require.Zero(t, peer.stale.Load(), "the upstream did not receive the current source value") })
	return &projectionFixture{r1: r1, r2: r2, digits: digits, sourcePath: sourcePath, peer: peer, client: client, releaseHeld: releaseHeld}
}

// TestCanonicalResponseProjection drives a declared host that reflects the
// source value it was sent, split across the records of each supported model
// stream, through the built proxy binary.
func TestCanonicalResponseProjection(t *testing.T) {
	f := newProjectionFixture(t)
	r1, r2, digits, peer, client, send, releaseHeld, sourcePath := f.r1, f.r2, f.digits, f.peer, f.client, f.send, f.releaseHeld, f.sourcePath

	t.Run("R1 then R2 cross-record reflected source values are projected", func(t *testing.T) {
		// A redeems R1 and is held after its first record.
		held, err := send("/v1/chat/completions", projectionBearer)
		require.NoError(t, err)
		defer held.Body.Close()

		// The source rotates; B and C redeem R2 while A is still open.
		writeSource(t, sourcePath, r2)
		peer.current.Store(&r2)
		time.Sleep(10 * time.Millisecond)
		messages := projectionBody(t, client, "/v1/messages")
		responses := projectionBody(t, client, "/v1/responses")

		releaseHeld()
		chat, err := io.ReadAll(held.Body)
		require.NoError(t, err)

		lanes := chatLanes(t, chat)
		require.True(t, lanes.content == "key="+projectionPlaceholder+" end \U0001F600", "chat content lane was not projected with A's R1 capture")
		require.True(t, lanes.reasoning == "think "+projectionPlaceholder, "chat reasoning lane was not projected")
		require.True(t, lanes.toolID == "call_1", "chat tool call id differs")
		requireToken(t, "chat tool arguments", lanes.arguments)
		var chatArgs map[string]json.RawMessage
		require.True(t, json.Unmarshal([]byte(lanes.arguments), &chatArgs) == nil, "chat tool arguments did not reassemble as JSON")
		_, heldKey := chatArgs[projectionPlaceholder]
		require.True(t, heldKey && len(chatArgs) == 2, "chat tool argument key was not projected with A's R1 capture")
		requireAbsent(t, "chat stream", string(chat)+lanes.content+lanes.reasoning+lanes.arguments, r1, r2)

		blocks := messageBlocks(t, messages)
		require.True(t, blocks[0] == "secret: "+projectionPlaceholder+"!", "anthropic text block was not projected")
		requireToken(t, "anthropic tool input", blocks[1])
		require.True(t, blocks[2] == "plan "+projectionPlaceholder+"sig", "anthropic thinking block was not projected")
		requireAbsent(t, "anthropic stream", string(messages)+blocks[0]+blocks[1]+blocks[2], r1, r2)

		deltas, done := responseItems(t, responses)
		require.True(t, len(deltas) == 1, "responses deltas named another item")
		requireToken(t, "responses argument deltas", deltas["fc_1"])
		requireToken(t, "responses done arguments", done["fc_1"])
		require.True(t, done["fc_1"] == deltas["fc_1"], "responses done arguments differ from the deltas")
		requireAbsent(t, "responses stream", string(responses)+deltas["fc_1"]+done["fc_1"], r1, r2)
	})

	t.Run("a numeric source in retry is projected or refused, never sent", func(t *testing.T) {
		resp, err := send("/v1/retry", numberHeader)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, 2, strings.Count(string(body), "retry: "+digitsPlaceholder+"\n"), "retry was not projected to the numeric placeholder")
		requireAbsent(t, "projected retry", string(body), digits)

		resp, err = send("/v1/retry", wordHeader)
		requireAbsent(t, "refused retry", requireIncomplete(t, resp, err), digits)
	})

	t.Run("protected JSON documents follow the strict token policy", func(t *testing.T) {
		resp, err := send("/v1/doc/valid", projectionBearer)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		requireAbsent(t, "valid document", string(body), r2)
		var doc map[string]json.RawMessage
		require.True(t, json.Unmarshal(body, &doc) == nil, "the valid document did not arrive whole")
		var token, cafe string
		require.True(t, json.Unmarshal(doc["token"], &token) == nil, "the valid document token is not a string")
		require.True(t, json.Unmarshal(doc["café"], &cafe) == nil, "the valid document café value is not a string")
		_, proto := doc["__proto__"]
		_, projectedKey := doc[projectionPlaceholder]
		require.True(t, token == projectionPlaceholder && projectedKey && proto, "the valid document lost its projected value, projected key or own __proto__")
		require.True(t, cafe == "été \U0001F600", "the valid document café value changed")

		for _, slug := range []string{"mismatched", "escape", "duplicate", "collision", "trailing"} {
			t.Run(slug, func(t *testing.T) {
				resp, err := send("/v1/doc/"+slug, projectionBearer)
				body := requireIncomplete(t, resp, err)
				requireAbsent(t, slug, body, r2)
			})
		}
	})

	t.Run("a protected stream that fails upstream aborts without its held suffix", func(t *testing.T) {
		for _, kind := range []string{"truncated", "protocol"} {
			t.Run(kind, func(t *testing.T) {
				resp, err := send("/v1/broken/"+kind, projectionBearer)
				body := requireIncomplete(t, resp, err)
				requireAbsent(t, kind, body, r2)
				require.False(t, strings.Contains(body, "[DONE]"), "a failed stream reached its end")
				select {
				case closed := <-peer.closed:
					require.True(t, closed, "the proxy kept the failed upstream connection open")
				case <-time.After(20 * time.Second):
					t.Fatal("the upstream never saw the failed connection end")
				}
			})
		}
	})

	t.Run("unknown, late and conflicting stream identities are refused", func(t *testing.T) {
		for _, slug := range []string{
			"responses-after-terminal", "responses-output-conflict", "responses-unknown-item",
			"anthropic-stop-before-start", "anthropic-delta-without-start", "anthropic-wrong-delta-type",
			"chat-tool-id-conflict", "chat-tool-without-id", "protocol-switch",
		} {
			t.Run(slug, func(t *testing.T) {
				resp, err := send("/v1/identity/"+slug, projectionBearer)
				require.False(t, strings.Contains(requireIncomplete(t, resp, err), "OFFENDING"), "the offending event was forwarded")
			})
		}
	})

	t.Run("event payloads are bounded before they are held", func(t *testing.T) {
		for _, slug := range []string{"deep", "values", "large"} {
			t.Run(slug, func(t *testing.T) {
				resp, err := send("/v1/bounds/"+slug, projectionBearer)
				requireIncomplete(t, resp, err)
			})
		}
		for _, slug := range []string{"deep-within", "large-within"} {
			t.Run(slug, func(t *testing.T) {
				body := projectionBody(t, client, "/v1/bounds/"+slug)
				events := projectedEvents(body)
				require.True(t, len(events) == 1, "a bounded stream event count differs")
				require.True(t, json.Valid([]byte(events[0].data)), "a bounded event did not arrive whole")
			})
		}
	})

	t.Run("unsupported protected modes are refused before an unprojected byte", func(t *testing.T) {
		cases := []struct {
			name, path string
			rejected   bool
		}{
			{name: "ndjson records", path: "/v1/records", rejected: true},
			{name: "untyped body", path: "/v1/untyped", rejected: true},
			{name: "unknown model event stream", path: "/v1/candidates"},
			{name: "event stream labelled json", path: "/v1/mislabeled"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp, err := send(tc.path, projectionBearer)
				if !tc.rejected {
					requireAbsent(t, tc.name, requireIncomplete(t, resp, err), r2)
					return
				}
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusBadGateway, resp.StatusCode)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				requireAbsent(t, tc.name, string(body), r2)
			})
		}
	})

	t.Run("unrelated binary and ordinary responses pass unchanged", func(t *testing.T) {
		resp, err := send("/v1/blob", projectionBearer)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, resp.Header.Get("Content-Type") == "image/png", "binary content type changed")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.True(t, bytes.Equal(peer.blob, body), "binary body changed")

		resp, err = send("/public/events", nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.True(t, string(body) == publicEvents, "public event stream changed")
	})
}

// TestCanonicalResponseProjectionReview drives the cases of the 2026-11-08
// review through the same real TLS fixture: valid model streams the
// projection must pass whole, responses to requests that redeem nothing,
// trailer names, values split across the chunks of a JSON array or the
// messages of a WebSocket, and a long event in small reads.
func TestCanonicalResponseProjectionReview(t *testing.T) {
	f := newProjectionFixture(t)
	r1, client, send := f.r1, f.client, f.send

	t.Run("valid model streams pass whole with their lanes projected", func(t *testing.T) {
		for slug, end := range map[string]string{
			"logprobs": "[DONE]", "reasoning-details": "[DONE]", "chat-tool-truncated": "[DONE]",
			"anthropic-tool-truncated": "message_stop", "responses-incomplete": "response.incomplete",
		} {
			t.Run(slug, func(t *testing.T) {
				resp, err := send("/v1/compat/"+slug, projectionBearer)
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err, "the stream was cut short")
				require.Contains(t, string(body), end)
				requireAbsent(t, slug, string(body), r1)
				if slug != "logprobs" {
					require.True(t, strings.Contains(string(body), projectionPlaceholder), "%s lost the placeholder", slug)
				}
			})
		}
	})

	t.Run("a response to a request that redeems nothing is scrubbed of what the grant redeemed", func(t *testing.T) {
		resp, err := send("/v1/header-ordinary", projectionBearer)
		require.NoError(t, err)
		resp.Body.Close()
		for _, path := range []string{"/v1/recall-json", "/v1/recall-text"} {
			resp, err := send(path, nil)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, path)
			requireAbsent(t, path, string(body), r1)
			require.True(t, strings.Contains(string(body), projectionPlaceholder), "%s lost the placeholder", path)
		}
	})

	t.Run("a trailer name that carries the value is refused", func(t *testing.T) {
		resp, err := send("/v1/trailer-name", projectionBearer)
		requireRefused(t, resp, err, r1)

		resp, err = send("/v1/trailer-late", projectionBearer)
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			for name := range resp.Trailer {
				requireAbsent(t, "trailer name", strings.ToLower(name), r1)
			}
		}
	})

	t.Run("a value split across the chunks of a JSON array is refused before it completes", func(t *testing.T) {
		resp, err := send("/v1beta/models/gemini:streamGenerateContent", projectionBearer)
		arrived := requireIncomplete(t, resp, err)
		require.False(t, strings.Contains(textsOf(arrived), r1), "the split value arrived whole")

		body := projectionBody(t, client, "/v1/list")
		require.True(t, string(body) == listDocument, "an ordinary list changed")
	})

	t.Run("a value split across websocket messages never arrives whole", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(ctx, "wss://"+projectionHost+"/v1/ws-split", &websocket.DialOptions{
			HTTPClient: client,
			HTTPHeader: http.Header{"Authorization": {"Bearer " + projectionPlaceholder}},
		})
		require.NoError(t, err)
		defer conn.CloseNow()
		var received strings.Builder
		for {
			_, message, err := conn.Read(ctx)
			if err != nil {
				break
			}
			received.Write(message)
		}
		require.False(t, strings.Contains(textsOf(received.String()), r1), "the split value arrived whole")
		require.False(t, strings.Contains(received.String(), "after"), "the relay went on after the split value")
	})

	t.Run("a credentialed response is scrubbed of a value from before a rotation", func(t *testing.T) {
		resp, err := send("/v1/header-ordinary", projectionBearer)
		require.NoError(t, err)
		resp.Body.Close()
		f.peer.old.Store(&r1)
		writeSource(t, f.sourcePath, f.r2)
		f.peer.current.Store(&f.r2)
		time.Sleep(10 * time.Millisecond)
		body := projectionBody(t, client, "/v1/recall-old")
		requireAbsent(t, "rotated value", string(body), r1)
		require.True(t, strings.Contains(string(body), projectionPlaceholder), "the rotated value lost the placeholder")
	})

	t.Run("a long event in small reads is projected in linear time", func(t *testing.T) {
		// Before the projector resumed its search, this event cost about 25 s
		// of CPU; linear work leaves it well under the bound.
		start := time.Now()
		body := projectionBody(t, client, "/v1/slow")
		require.Less(t, time.Since(start), 8*time.Second)
		require.Greater(t, len(body), slowEventBytes)
	})
}

var textField = regexp.MustCompile(`"(?:text|delta)":"([^"]*)"`)

// textsOf joins the text and delta strings in text, in order, as a client
// reassembling a model stream's text would.
func textsOf(text string) string {
	var b strings.Builder
	for _, match := range textField.FindAllStringSubmatch(text, -1) {
		b.WriteString(match[1])
	}
	return b.String()
}

// TestCanonicalResponseProjectionRefusals drives the header-name, invalid
// projection, Responses part, clean-EOF, tool-argument and matched-MCP bound
// cases through the same real TLS fixture.
func TestCanonicalResponseProjectionRefusals(t *testing.T) {
	f := newProjectionFixture(t)
	r2, digits, client, send := f.r2, f.digits, f.client, f.send
	// The source rotates to R2 first, so these cases reflect the value the
	// earlier test's later cases saw.
	writeSource(t, f.sourcePath, r2)
	f.peer.current.Store(&r2)
	time.Sleep(10 * time.Millisecond)

	t.Run("a credential reflected as a response header name is refused", func(t *testing.T) {
		// Go canonicalizes the lowercase name before the case-sensitive value
		// scrub; a lowercasing client would otherwise recover it. The response
		// is refused with a 502 that carries none of the value.
		resp, err := send("/v1/header-name", projectionBearer)
		requireRefused(t, resp, err, r2)

		// An ordinary header passes through unchanged to a lowercasing client.
		resp, err = send("/v1/header-ordinary", projectionBearer)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, resp.Header.Get("X-Owned-Ordinary") == "ok", "the ordinary header changed")

		// A base32-derived name is projected to the placeholder's derived name.
		derived, ordinary := base32Fragment(r2), base32Fragment(projectionPlaceholder)
		resp, err = send("/v1/header-derived", projectionBearer)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, resp.Header.Get(ordinary) == "1", "the derived header name was not projected")
		for name := range resp.Header {
			requireAbsent(t, "projected header name", strings.ToLower(name), r2, derived)
		}

		// Beside an ordinary header of that name in another case, the two would
		// merge on forwarding, so the response is refused before it.
		resp, err = send("/v1/header-collision", projectionBearer)
		requireRefused(t, resp, err, r2, derived)
	})

	t.Run("a projection that would make JSON invalid is refused, valid projections complete", func(t *testing.T) {
		// Numeric credential in a numeric position under a word placeholder:
		// the completed JSON would be malformed, so the response is refused.
		resp, err := send("/v1/jsondoc/number", wordHeader)
		requireAbsent(t, "invalid numeric document", requireIncomplete(t, resp, err), digits)

		// Numeric placeholder in the same numeric position stays valid JSON.
		resp, err = send("/v1/jsondoc/number", numberHeader)
		require.NoError(t, err)
		defer resp.Body.Close()
		numBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var numDoc map[string]json.RawMessage
		require.True(t, json.Unmarshal(numBody, &numDoc) == nil, "the numeric document did not arrive whole")
		require.True(t, string(numDoc["count"]) == digitsPlaceholder, "the numeric document count was not projected to the numeric placeholder")
		requireAbsent(t, "numeric document", string(numBody), digits)

		// A word placeholder in a string position stays valid JSON.
		resp, err = send("/v1/jsondoc/string", wordHeader)
		require.NoError(t, err)
		defer resp.Body.Close()
		strBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var strDoc map[string]string
		require.True(t, json.Unmarshal(strBody, &strDoc) == nil, "the string document did not arrive whole")
		require.True(t, strDoc["s"] == wordPlaceholder, "the string document value was not projected to the word placeholder")
		requireAbsent(t, "string document", string(strBody), digits)
	})

	t.Run("an SSE record projected to invalid JSON is refused on finish", func(t *testing.T) {
		resp, err := send("/v1/jsonsse", wordHeader)
		requireAbsent(t, "invalid sse record", requireIncomplete(t, resp, err), digits)

		resp, err = send("/v1/jsonsse", numberHeader)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		events := projectedEvents(body)
		require.True(t, len(events) == 1, "the numeric sse event count differs")
		require.True(t, json.Valid([]byte(events[0].data)), "a projected record did not arrive as valid JSON")
		require.True(t, strings.Contains(events[0].data, digitsPlaceholder), "the numeric sse record does not carry the numeric placeholder")
		requireAbsent(t, "numeric sse record", string(body), digits)
	})

	t.Run("a Responses content part fences a later lane at its index", func(t *testing.T) {
		valid := projectionBody(t, client, "/v1/responses-parts/valid")
		var text string
		for _, ev := range projectedEvents(valid) {
			var e struct {
				Type, Delta string
			}
			require.True(t, json.Unmarshal([]byte(ev.data), &e) == nil, "a responses part event is not JSON")
			if e.Type == "response.output_text.delta" {
				text += e.Delta
			}
		}
		require.True(t, text == "secret: "+projectionPlaceholder, "the message part was not projected")
		requireAbsent(t, "responses part", string(valid)+text, r2)

		for _, slug := range []string{"refusal-after-text", "unknown-part"} {
			t.Run(slug, func(t *testing.T) {
				resp, err := send("/v1/responses-parts/"+slug, projectionBearer)
				require.False(t, strings.Contains(requireIncomplete(t, resp, err), "OFFENDING"), "the offending part was forwarded")
			})
		}
	})

	t.Run("a clean EOF of an unfinished stream drops the held prefix and refuses", func(t *testing.T) {
		resp, err := send("/v1/early-eof", projectionBearer)
		body := requireIncomplete(t, resp, err)
		requireAbsent(t, "early eof", body, r2)
		require.False(t, strings.Contains(body, "[DONE]"), "an unfinished stream reached its end")
	})

	t.Run("a credential reflected in nested escaped arguments is projected", func(t *testing.T) {
		body := projectionBody(t, client, "/v1/nested")
		deltas, done := responseItems(t, body)
		var args map[string]json.RawMessage
		require.True(t, json.Unmarshal([]byte(deltas["fc_1"]), &args) == nil, "the nested arguments did not reassemble as JSON")
		var echo string
		require.True(t, json.Unmarshal(args["echo"], &echo) == nil, "the nested echo is not a string")
		require.True(t, echo == projectionPlaceholder, "the nested value was not projected")
		_, projectedKey := args[projectionPlaceholder]
		require.True(t, projectedKey, "the nested key was not projected")
		requireAbsent(t, "nested arguments", string(body)+deltas["fc_1"]+done["fc_1"], r2)
	})

	t.Run("tool arguments are projected whole under the strict JSON policy", func(t *testing.T) {
		for _, family := range []string{"chat", "anthropic", "function_call", "mcp_call"} {
			t.Run(family, func(t *testing.T) {
				body := projectionBody(t, client, "/v1/args/"+family+"-escaped")
				args, done := reassembledArguments(t, family, body)
				requireEscapedArguments(t, family, args)
				require.True(t, done == args || family == "chat" || family == "anthropic", "%s done arguments differ from the deltas", family)
				requireAbsent(t, family+" escaped arguments", string(body)+args+done, r2)
				for _, kind := range []string{"collision", "malformed", "unclosed", "escape", "surrogate"} {
					resp, err := send("/v1/args/"+family+"-"+kind, projectionBearer)
					refused := requireIncomplete(t, resp, err)
					requireAbsent(t, family+" "+kind, refused, r2)
					// The collision carries the placeholder itself: no argument
					// byte may be published before the whole is admitted.
					require.False(t, strings.Contains(refused, projectionPlaceholder), "%s %s published part of its arguments", family, kind)
				}
			})
		}
	})

	t.Run("a Responses item's complete argument copies agree with its deltas once", func(t *testing.T) {
		for _, family := range []string{"function_call", "mcp_call"} {
			t.Run(family, func(t *testing.T) {
				// Each copy spells the same value with other escapes; it completes.
				body := projectionBody(t, client, "/v1/copies/"+family+"-respelled")
				args, done := reassembledArguments(t, family, body)
				requireEscapedArguments(t, family+" respelled deltas", args)
				requireEscapedArguments(t, family+" respelled done", done)
				requireAbsent(t, family+" respelled arguments", string(body)+args+done, r2)
				doneType := `"type":"response.` + family + `_arguments.done"`
				otherKind := "function_call"
				if family == "function_call" {
					otherKind = "mcp_call"
				}
				for _, fault := range []struct{ kind, changedKind string }{
					{"done-differs", ""}, {"item-differs", ""}, {"duplicate-done", ""}, {"late-done", ""},
					{"kind-differs", otherKind}, {"kind-message", "message"},
				} {
					resp, err := send("/v1/copies/"+family+"-"+fault.kind, projectionBearer)
					refused := requireIncomplete(t, resp, err)
					requireAbsent(t, family+" "+fault.kind, refused, r2)
					require.True(t, !strings.Contains(refused, "OFFENDING") && strings.Count(refused, doneType) <= 1,
						"%s %s published a differing, repeated or late argument copy", family, fault.kind)
					require.True(t, fault.changedKind == "" || !strings.Contains(refused, `"type":"`+fault.changedKind+`"`),
						"%s %s published the changed-kind item", family, fault.kind)
				}
			})
		}
	})

	t.Run("a matched MCP server's protected document is bounded and its upstream closed", func(t *testing.T) {
		resp, err := send("/mcp", projectionBearer)
		requireAbsent(t, "bounded mcp document", requireIncomplete(t, resp, err), r2)
		select {
		case closed := <-f.peer.closed:
			require.True(t, closed, "the proxy read the whole oversized document")
		case <-time.After(20 * time.Second):
			t.Fatal("the upstream never saw the bounded connection end")
		}
	})
}

// projectionSecret is 48 hex characters that start with a letter, so Go's
// canonical form of it as a field name differs from it.
func projectionSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 24)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return "a" + hex.EncodeToString(raw)[1:]
}

// digitsSecret is a 30-digit decimal source value. Its first digit is 1-9, so
// it is a valid JSON number where the peer reflects it unquoted.
func digitsSecret(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for b.Len() < 30 {
		span, low := int64(10), int64(0)
		if b.Len() == 0 {
			span, low = 9, 1
		}
		n, err := rand.Int(rand.Reader, big.NewInt(span))
		require.NoError(t, err)
		b.WriteByte(byte('0' + low + n.Int64()))
	}
	return b.String()
}

func writeSource(t *testing.T, path, value string) {
	t.Helper()
	next := path + ".next"
	require.NoError(t, os.WriteFile(next, []byte(value), 0o600))
	require.NoError(t, os.Rename(next, path))
}

func projectionSend(client *http.Client, path string, credential map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, "https://"+projectionHost+path, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range credential {
		req.Header.Set(name, value)
	}
	return client.Do(req)
}

func projectionBody(t *testing.T, client *http.Client, path string) []byte {
	t.Helper()
	resp, err := projectionSend(client, path, projectionBearer)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

// requireIncomplete checks a refused response never reached the client as a
// complete body: the connection ends before a response or inside its body.
// It returns what did arrive.
func requireIncomplete(t *testing.T, resp *http.Response, err error) string {
	t.Helper()
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.Error(t, readErr, "a refused response ended as a complete body")
	return string(body)
}

type projectedEvent struct{ name, data string }

// projectedEvents reads a server-sent event stream the way a client does.
func projectedEvents(body []byte) []projectedEvent {
	var events []projectedEvent
	var current projectedEvent
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case line == "":
			if current.data != "" {
				events = append(events, current)
			}
			current = projectedEvent{}
		case strings.HasPrefix(line, "event: "):
			current.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			if current.data != "" {
				current.data += "\n"
			}
			current.data += strings.TrimPrefix(line, "data: ")
		}
	}
	return events
}

type chatResult struct{ content, reasoning, arguments, toolID string }

// chatLanes joins chunks by choice and tool call index, as a client does.
func chatLanes(t *testing.T, body []byte) chatResult {
	t.Helper()
	var result chatResult
	for _, ev := range projectedEvents(body) {
		if ev.data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		require.True(t, json.Unmarshal([]byte(ev.data), &chunk) == nil, "a chat chunk is not JSON")
		for _, choice := range chunk.Choices {
			require.Zero(t, choice.Index)
			result.content += choice.Delta.Content
			result.reasoning += choice.Delta.ReasoningContent
			for _, call := range choice.Delta.ToolCalls {
				require.Zero(t, call.Index)
				result.arguments += call.Function.Arguments
				if call.ID != "" {
					require.True(t, result.toolID == "" || result.toolID == call.ID, "tool call id changed")
					result.toolID = call.ID
				}
			}
		}
	}
	return result
}

// messageBlocks joins Anthropic events by content block index.
func messageBlocks(t *testing.T, body []byte) map[int]string {
	t.Helper()
	blocks := map[int]string{}
	for _, ev := range projectedEvents(body) {
		var event struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Text     string `json:"text"`
				Thinking string `json:"thinking"`
			} `json:"content_block"`
			Delta struct {
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				Thinking    string `json:"thinking"`
				Signature   string `json:"signature"`
			} `json:"delta"`
		}
		require.True(t, json.Unmarshal([]byte(ev.data), &event) == nil, "an anthropic event is not JSON")
		require.True(t, event.Type == ev.name, "an anthropic event name differs from its type")
		if event.Type == "content_block_start" || event.Type == "content_block_delta" {
			blocks[event.Index] += event.ContentBlock.Text + event.ContentBlock.Thinking +
				event.Delta.Text + event.Delta.PartialJSON + event.Delta.Thinking + event.Delta.Signature
		}
	}
	return blocks
}

// responseItems joins Responses argument deltas and done events by item.
func responseItems(t *testing.T, body []byte) (map[string]string, map[string]string) {
	t.Helper()
	deltas, done := map[string]string{}, map[string]string{}
	for _, ev := range projectedEvents(body) {
		var event struct {
			Type      string `json:"type"`
			ItemID    string `json:"item_id"`
			Delta     string `json:"delta"`
			Arguments string `json:"arguments"`
		}
		require.True(t, json.Unmarshal([]byte(ev.data), &event) == nil, "a responses event is not JSON")
		require.True(t, event.Type == ev.name, "a responses event name differs from its type")
		switch event.Type {
		case "response.function_call_arguments.delta", "response.mcp_call_arguments.delta":
			deltas[event.ItemID] += event.Delta
		case "response.function_call_arguments.done", "response.mcp_call_arguments.done":
			done[event.ItemID] = event.Arguments
		}
	}
	return deltas, done
}

// reassembledArguments joins one tool call's arguments as its family's client
// does, with the arguments a Responses done event repeats.
func reassembledArguments(t *testing.T, family string, body []byte) (string, string) {
	t.Helper()
	switch family {
	case "chat":
		return chatLanes(t, body).arguments, ""
	case "anthropic":
		return messageBlocks(t, body)[0], ""
	}
	deltas, done := responseItems(t, body)
	return deltas["fc_1"], done["fc_1"]
}

// requireEscapedArguments checks the escaped arguments decode with the
// placeholder in the quoted value and in the backslashed key.
func requireEscapedArguments(t *testing.T, surface, arguments string) {
	t.Helper()
	var args map[string]json.RawMessage
	require.True(t, json.Unmarshal([]byte(arguments), &args) == nil, "%s arguments did not reassemble as JSON", surface)
	var note string
	require.True(t, json.Unmarshal(args["note"], &note) == nil, "%s note is not a string", surface)
	require.True(t, note == `say "`+projectionPlaceholder+`" at C:\ é`, "%s escaped value was not projected", surface)
	_, key := args[`"`+projectionPlaceholder+`\`]
	require.True(t, key && len(args) == 2, "%s escaped key was not projected", surface)
}

// requireRefused checks a response was replaced by a 502 whose header names
// and body carry no part of the values.
func requireRefused(t *testing.T, resp *http.Response, err error, values ...string) {
	t.Helper()
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	for name := range resp.Header {
		requireAbsent(t, "refused header name", strings.ToLower(name), values...)
	}
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	requireAbsent(t, "refused body", string(body), values...)
}

// requireToken checks reassembled tool-call JSON names the placeholder.
func requireToken(t *testing.T, surface, arguments string) {
	t.Helper()
	var parsed struct {
		Token string `json:"token"`
	}
	require.True(t, json.Unmarshal([]byte(arguments), &parsed) == nil, "%s is not JSON with a string token", surface)
	require.True(t, parsed.Token == projectionPlaceholder, "%s was not projected", surface)
}

// requireAbsent fails when any eight-character run of a held value appears in
// text. It never prints the text or the value.
func requireAbsent(t *testing.T, surface, text string, values ...string) {
	t.Helper()
	for _, value := range values {
		for i := 0; i+8 <= len(value); i++ {
			require.False(t, strings.Contains(text, value[i:i+8]), "%s carries part of a held value", surface)
		}
	}
}
