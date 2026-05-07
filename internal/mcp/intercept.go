package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// mediaTypeIs reports whether ct names the given media type, ignoring case
// and any parameters (e.g. "; charset=utf-8"). RFC 7231 §3.1.1.1 requires
// case-insensitive comparison of type and subtype.
func mediaTypeIs(ct, want string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == want
}

// EvaluateRequest applies the policy to an MCP request that has already
// matched a configured server. When the request should be rejected, returns a
// non-nil http.Response that the proxy must write to the client (and skip the
// upstream call). When it returns (nil, nil), the request is allowed; the
// caller forwards to upstream and then invokes WrapResponseBody on the
// response. When err is non-nil, the proxy should treat it as a 502.
//
// The req.Body must be a *transform.BufferedBody. EvaluateRequest reads it
// and resets so subsequent transforms (and the upstream forward) re-read
// cleanly.
func (p *Policy) EvaluateRequest(server *Server, req *http.Request, trace *Trace) (*http.Response, error) {
	if p == nil || server == nil {
		return nil, nil
	}

	// We only inspect application/json POST requests. GET listeners and other
	// shapes pass through; their responses are still wrapped if they arrive
	// over text/event-stream so the listener stream is filtered.
	if req.Method != http.MethodPost {
		return nil, nil
	}
	if !mediaTypeIs(req.Header.Get("Content-Type"), "application/json") {
		return nil, nil
	}

	bb, ok := req.Body.(*transform.BufferedBody)
	if !ok {
		return nil, fmt.Errorf("mcp: expected *transform.BufferedBody, got %T", req.Body)
	}
	body, err := io.ReadAll(bb)
	if err != nil {
		return nil, fmt.Errorf("mcp: reading request body: %w", err)
	}
	bb.Reset()

	// Detect oversize: if the upstream Content-Length exceeded the buffered
	// body cap, the read returned a truncated body. We cannot reliably parse
	// JSON-RPC in that case, so deny.
	if req.ContentLength > 0 && int64(len(body)) < req.ContentLength {
		trace.Append(Message{
			Direction: DirectionRequest,
			Decision:  DecisionDeny,
			Reason:    ReasonOversizeBody,
		})
		return p.errorResponse(req, nil, false), nil
	}

	msgs, isBatch, err := decodeJSONRPC(body)
	if err != nil {
		trace.Append(Message{
			Direction: DirectionRequest,
			Decision:  DecisionDeny,
			Reason:    ReasonMalformedJSONRPC,
		})
		return p.errorResponse(req, nil, isBatch), nil
	}

	denyAny := false
	ids := make([]json.RawMessage, len(msgs))
	for i, m := range msgs {
		ids[i] = m.ID
		entry := Message{
			Direction: DirectionRequest,
			Method:    m.Method,
			Decision:  DecisionAllow,
		}
		switch m.Method {
		case MethodToolsCall:
			name, args, ok := extractToolCallName(m.Params)
			entry.Tool = name
			if !ok {
				entry.Decision = DecisionDeny
				entry.Reason = ReasonMalformedJSONRPC
				denyAny = true
			} else if allowed, reason := server.EvaluateTool(name, args); !allowed {
				entry.Decision = DecisionDeny
				entry.Reason = reason
				denyAny = true
			}
		case MethodToolsList:
			// Record the request id so the response wrapper knows this
			// specific response is the one whose tools array should be
			// filtered. Other JSON-RPC results that happen to contain a
			// tools array are left alone.
			trace.recordToolsListID(m.ID)
		}
		trace.Append(entry)
	}

	if !denyAny {
		return nil, nil
	}

	if isBatch {
		body, err := batchErrorResponseBody(ids, p.errorCode, p.errorMessage)
		if err != nil {
			return nil, fmt.Errorf("mcp: building batch error response: %w", err)
		}
		return jsonRPCResponse(req, body), nil
	}
	body2, err := errorResponseBody(ids[0], p.errorCode, p.errorMessage)
	if err != nil {
		return nil, fmt.Errorf("mcp: building error response: %w", err)
	}
	return jsonRPCResponse(req, body2), nil
}

// errorResponse builds a synthetic JSON-RPC error envelope to return when a
// request is denied without per-item ids (malformed/oversize cases).
func (p *Policy) errorResponse(req *http.Request, _ json.RawMessage, isBatch bool) *http.Response {
	var body []byte
	var err error
	if isBatch {
		body, err = batchErrorResponseBody([]json.RawMessage{nil}, p.errorCode, p.errorMessage)
	} else {
		body, err = errorResponseBody(nil, p.errorCode, p.errorMessage)
	}
	if err != nil {
		// Should not happen — fall back to a plain 403.
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Forbidden",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          http.NoBody,
			Request:       req,
			ContentLength: 0,
		}
	}
	return jsonRPCResponse(req, body)
}

// jsonRPCResponse wraps a JSON-RPC response body in an http.Response. The
// proxy's writeResponse copies headers and body so we always return 200 OK
// with application/json — JSON-RPC errors are encoded inside the envelope.
func jsonRPCResponse(req *http.Request, body []byte) *http.Response {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
	}
}

// WrapResponseBody installs the response-side filter for an MCP-matched
// response. The returned body must replace resp.Body before the proxy's
// streaming or buffered writeResponse path runs.
//
// Behavior depends on Content-Type:
//   - application/json: read and decode the full body, filter tools/list
//     results, re-marshal, return a NewBufferedBodyFromBytes wrapper.
//   - text/event-stream: return a streaming reader that scans events as they
//     arrive, decodes the data payload as JSON-RPC, filters tools/list result
//     payloads, and re-emits the event. Other event shapes pass through.
//   - anything else: returns the original body unchanged.
func (p *Policy) WrapResponseBody(server *Server, contentType string, body io.ReadCloser, trace *Trace) (io.ReadCloser, error) {
	if p == nil || server == nil {
		return body, nil
	}
	allowed := server.AllowedToolNames()

	if mediaTypeIs(contentType, "text/event-stream") {
		return newSSEFilter(body, allowed, trace), nil
	}
	if !mediaTypeIs(contentType, "application/json") {
		return body, nil
	}

	raw, err := io.ReadAll(body)
	closeErr := body.Close()
	if err != nil {
		return nil, fmt.Errorf("mcp: reading response body: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("mcp: closing upstream response body: %w", closeErr)
	}

	filtered, err := filterJSONResponseBody(raw, allowed, trace)
	if err != nil {
		// On filter failure, pass the original body through untouched.
		return transform.NewBufferedBodyFromBytes(raw), nil
	}
	return transform.NewBufferedBodyFromBytes(filtered), nil
}

// filterJSONResponseBody filters tools/list responses inside a non-streaming
// JSON body. The body may be a single JSON-RPC response or a batch. Only
// responses whose id was previously recorded as a tools/list request are
// rewritten; other results are emitted unchanged so a tools/call result that
// happens to contain a tools array is left alone.
func filterJSONResponseBody(raw []byte, allowed map[string]bool, trace *Trace) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, nil
	}
	if trimmed[0] == '[' {
		var batch []rpcMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, err
		}
		changed := false
		for i := range batch {
			removed := 0
			if trace.isToolsListResponse(batch[i].ID) {
				_, removed = filterMessageInPlace(&batch[i], allowed)
			}
			appendResponseAudit(trace, batch[i], removed)
			if removed > 0 {
				changed = true
			}
		}
		if !changed {
			return raw, nil
		}
		return json.Marshal(batch)
	}
	var single rpcMessage
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	removed := 0
	if trace.isToolsListResponse(single.ID) {
		_, removed = filterMessageInPlace(&single, allowed)
	}
	appendResponseAudit(trace, single, removed)
	if removed == 0 {
		return raw, nil
	}
	return json.Marshal(single)
}

// filterMessageInPlace mutates msg.Result if its tools array contains entries
// not in allowed. Caller is responsible for ensuring this is a tools/list
// response (via trace.isToolsListResponse) before invoking — otherwise an
// unrelated result whose payload happens to carry a top-level tools array
// would be rewritten.
func filterMessageInPlace(msg *rpcMessage, allowed map[string]bool) (json.RawMessage, int) {
	if len(msg.Result) == 0 {
		return msg.Result, 0
	}
	newRes, removed, err := filterToolsListResult(msg.Result, allowed)
	if err != nil || removed == 0 {
		return msg.Result, 0
	}
	msg.Result = newRes
	return newRes, removed
}

// appendResponseAudit records a single response-side audit entry for a
// JSON-RPC message. We do not always know the method on a response (servers
// echo only the id), so method is left blank unless the message itself was a
// server-initiated request carrying a method.
func appendResponseAudit(trace *Trace, msg rpcMessage, filtered int) {
	if trace == nil {
		return
	}
	entry := Message{
		Direction: DirectionResponse,
		Method:    msg.Method,
		Decision:  DecisionAllow,
	}
	if filtered > 0 {
		entry.Method = MethodToolsList
		entry.Decision = DecisionFiltered
		entry.Filtered = filtered
	}
	trace.Append(entry)
}

// sseFilter streams SSE events from upstream, filters JSON-RPC payloads, and
// re-emits the events to the client. It implements io.ReadCloser. Reads are
// driven by the proxy's streamSSE flush loop — each call returns enough bytes
// to make forward progress; we buffer at most one rewritten event at a time.
type sseFilter struct {
	upstream io.ReadCloser
	br       *bufio.Reader
	allowed  map[string]bool
	trace    *Trace
	pending  []byte
	done     bool
}

func newSSEFilter(upstream io.ReadCloser, allowed map[string]bool, trace *Trace) io.ReadCloser {
	return &sseFilter{
		upstream: upstream,
		br:       bufio.NewReader(upstream),
		allowed:  allowed,
		trace:    trace,
	}
}

func (f *sseFilter) Read(p []byte) (int, error) {
	if len(f.pending) > 0 {
		n := copy(p, f.pending)
		f.pending = f.pending[n:]
		return n, nil
	}
	if f.done {
		return 0, io.EOF
	}
	ev, err := readSSEEvent(f.br)
	if ev != nil {
		f.handleEvent(ev)
	}
	if err != nil {
		f.done = true
		if err == io.EOF && len(f.pending) > 0 {
			// Flush trailing buffered bytes before EOF.
			n := copy(p, f.pending)
			f.pending = f.pending[n:]
			if len(f.pending) == 0 {
				return n, io.EOF
			}
			return n, nil
		}
		if err != io.EOF {
			return 0, err
		}
		if len(f.pending) == 0 {
			return 0, io.EOF
		}
	}
	if len(f.pending) == 0 {
		return 0, nil
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *sseFilter) handleEvent(ev *sseEvent) {
	payload := ev.dataPayload()
	if len(payload) == 0 {
		f.pending = append(f.pending, ev.raw...)
		return
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		f.pending = append(f.pending, ev.raw...)
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		f.pending = append(f.pending, ev.raw...)
		return
	}
	removed := 0
	if f.trace.isToolsListResponse(msg.ID) {
		_, removed = filterMessageInPlace(&msg, f.allowed)
	}
	appendResponseAudit(f.trace, msg, removed)
	if removed == 0 {
		f.pending = append(f.pending, ev.raw...)
		return
	}
	newPayload, err := json.Marshal(msg)
	if err != nil {
		f.pending = append(f.pending, ev.raw...)
		return
	}
	f.pending = append(f.pending, ev.rewriteData(newPayload)...)
}

func (f *sseFilter) Close() error {
	return f.upstream.Close()
}
