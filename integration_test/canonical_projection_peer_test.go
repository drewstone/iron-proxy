package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// projectionPeer is the declared host. Each endpoint reflects the source
// value it received, split across records, inside JSON escapes and across
// HTTP chunks, or breaks a protocol rule after reflecting it.
type projectionPeer struct {
	current *atomic.Pointer[string]
	old     atomic.Pointer[string]
	digits  string
	stale   atomic.Int32
	release chan struct{}
	blob    []byte
	// closed reports, for each broken stream, whether the proxy closed the
	// upstream connection after the failure.
	closed chan bool
}

type peerEvent struct{ name, data string }

func (peer *projectionPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/public/events" {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, publicEvents) // A write error is the client's to see.
		return
	}
	if path == "/v1/recall-old" {
		// A credentialed request whose answer is a value the host was sent
		// before the source rotated.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "stored="+*peer.old.Load())
		return
	}
	if strings.HasPrefix(path, "/v1/recall-") {
		// Answers a request with no credential with what the host was sent
		// before, as a host that stores a credential can.
		stored := *peer.current.Load()
		if path == "/v1/recall-json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"stored":"`+stored+`"}`)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "stored="+stored)
		return
	}
	want, value := *peer.current.Load(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if path == "/v1/retry" || strings.HasPrefix(path, "/v1/jsondoc/") || path == "/v1/jsonsse" {
		want, value = peer.digits, r.Header.Get("X-Digits-Number")+r.Header.Get("X-Digits-Word")
	}
	if value != want || len(value) < 24 {
		peer.stale.Add(1)
		http.Error(w, "unexpected credential", http.StatusUnauthorized)
		return
	}
	sse := func() { w.Header().Set("Content-Type", "text/event-stream") }
	// Write errors below are surfaced to the client as a broken stream.
	switch slug := path[strings.LastIndex(path, "/")+1:]; {
	case path == "/v1/chat/completions":
		sse()
		writeChat(w, value, peer.release)
	case path == "/v1/messages":
		sse()
		writeMessages(w, value)
	case path == "/v1/responses":
		sse()
		writeResponses(w, value)
	case path == "/v1/retry":
		sse()
		writeRaw(w, "retry: "+value+"\n\n")
		writeRaw(w, "event: message\nretry: "+value+"\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
	case strings.HasPrefix(path, "/v1/doc/"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, jsonDocument(slug, value))
	case strings.HasPrefix(path, "/v1/broken/"):
		sse()
		peer.writeBroken(w, slug, value)
	case strings.HasPrefix(path, "/v1/identity/"):
		sse()
		for _, ev := range identityEvents(slug) {
			writeEvent(w, ev.name, ev.data)
		}
	case strings.HasPrefix(path, "/v1/bounds/"):
		sse()
		for _, ev := range boundsEvents(slug) {
			writeEvent(w, ev.name, ev.data)
		}
	case path == "/v1/records":
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = fmt.Fprintf(w, "{\"text\":%q}\n{\"text\":%q}\n", value[:24], value[24:])
	case path == "/v1/untyped":
		w.Header()["Content-Type"] = nil
		_, _ = io.WriteString(w, value[:24]+"\n"+value[24:])
	case path == "/v1/candidates":
		sse()
		for _, part := range []string{value[:24], value[24:]} {
			writeEvent(w, "", `{"candidates":[{"content":{"parts":[{"text":"`+part+`"}]}}]}`)
		}
	case path == "/v1/mislabeled":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "data: {\"text\":\""+value[:24]+"\"}\n\ndata: {\"text\":\""+value[24:]+"\"}\n\n")
	case path == "/v1/blob":
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(peer.blob)
	case path == "/v1/header-name":
		// Reflect the credential as a response field name. The map key is set
		// directly so the fixture does not canonicalize it; Go canonicalizes it
		// when the proxy reads the response, defeating a case-sensitive needle.
		w.Header()[value] = []string{"1"}
		w.Header().Set("X-Owned-Ordinary", "ok")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	case path == "/v1/header-ordinary":
		w.Header().Set("X-Owned-Ordinary", "ok")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	case path == "/v1/early-eof":
		// One admitted chunk whose content ends in a proper prefix of the
		// credential, then a clean HTTP end with no choice finish or [DONE].
		sse()
		writeEvent(w, "", chatChunk(`{"role":"assistant","content":"key=`+value[:8]+`"}`, "null"))
	case strings.HasPrefix(path, "/v1/jsondoc/"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, jsonNumberDocument(slug, value))
	case path == "/v1/jsonsse":
		sse()
		writeEvent(w, "", `{"error":{"message":"x","code":`+value+`}}`)
	case strings.HasPrefix(path, "/v1/responses-parts/"):
		sse()
		for _, ev := range responsesPartEvents(slug, value) {
			writeEvent(w, ev.name, ev.data)
		}
	case path == "/v1/nested":
		sse()
		writeNested(w, value)
	case strings.HasPrefix(path, "/v1/args/"):
		sse()
		family, kind, _ := strings.Cut(slug, "-")
		for _, ev := range argumentEvents(family, argumentText(kind, value)) {
			writeEvent(w, ev.name, ev.data)
		}
	case strings.HasPrefix(path, "/v1/copies/"):
		sse()
		family, kind, _ := strings.Cut(slug, "-")
		for _, ev := range copyEvents(family, kind, value) {
			writeEvent(w, ev.name, ev.data)
		}
	case path == "/v1/header-derived" || path == "/v1/header-collision":
		// The credential's base32 spelling as a field name, which projects to
		// the placeholder's; the collision adds an ordinary header of that name.
		w.Header()[base32Fragment(value)] = []string{"1"}
		if path == "/v1/header-collision" {
			w.Header().Set(base32Fragment(projectionPlaceholder), "2")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	case path == "/mcp":
		peer.writeUnbounded(w, value)
	case strings.HasPrefix(path, "/v1/compat/"):
		sse()
		for _, ev := range compatEvents(slug, value) {
			writeEvent(w, ev.name, ev.data)
		}
	case path == "/v1/trailer-name":
		// A declared trailer named by the value, set after the body.
		w.Header()["Trailer"] = []string{value}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		w.Header()[value] = []string{"1"}
	case path == "/v1/trailer-late":
		// An undeclared trailer named by the value, after a whole chat stream.
		sse()
		writeEvent(w, "", chatChunk(`{"role":"assistant","content":"hi"}`, `"stop"`))
		writeEvent(w, "", "[DONE]")
		w.Header()[http.TrailerPrefix+value] = []string{"1"}
	case path == "/v1beta/models/gemini:streamGenerateContent":
		// A model stream sent as one JSON array, the value split across two
		// of its chunks.
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		writeRaw(w, `[{"candidates":[{"content":{"parts":[{"text":"key=`+value[:24]+`"}],"role":"model"},"index":0}]}`)
		time.Sleep(2 * time.Millisecond)
		writeRaw(w, ",\r\n"+`{"candidates":[{"content":{"parts":[{"text":"`+value[24:]+` end"}],"role":"model"},"index":0}]}]`)
	case path == "/v1/list":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, listDocument)
	case path == "/v1/ws-split":
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for _, message := range []string{`{"type":"response.output_text.delta","delta":"key=` + value[:24] + `"}`, `{"type":"response.output_text.delta","delta":"` + value[24:] + ` end"}`, "after"} {
			if conn.Write(r.Context(), websocket.MessageText, []byte(message)) != nil {
				return
			}
		}
		_, _, _ = conn.Read(r.Context())
	case path == "/v1/slow":
		// One long content event written in small flushes.
		sse()
		event := "data: " + chatChunk(`{"role":"assistant","content":"`+strings.Repeat("a", slowEventBytes)+`"}`, "null") + "\n\n"
		for at := 0; at < len(event); at += slowFlushBytes {
			_, _ = io.WriteString(w, event[at:min(at+slowFlushBytes, len(event))])
			w.(http.Flusher).Flush()
		}
		writeEvent(w, "", chatChunk(`{}`, `"stop"`))
		writeEvent(w, "", "[DONE]")
	default:
		http.NotFound(w, r)
	}
}

const (
	slowEventBytes = 3 << 20
	slowFlushBytes = 64
)

// listDocument is an ordinary JSON list of objects that holds no value.
const listDocument = `[{"name":"one","text":"alpha"},{"name":"two","text":"beta"}]`

func chatChunkWith(choice string) string {
	return `{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[` + choice + `]}`
}

// compatEvents are valid model streams the projection must pass whole: chat
// log probabilities, OpenRouter reasoning details, and tool calls cut off at
// the length limit in each protocol. Reasoning and tool input carry the value.
func compatEvents(slug, value string) []peerEvent {
	logprob := func(token string) string {
		return `{"token":"` + token + `","logprob":-0.1,"bytes":[104],"top_logprobs":[{"token":"` + token + `","logprob":-0.1,"bytes":[104]}]}`
	}
	detail := func(text string) string {
		return chatChunk(`{"role":"assistant","content":"","reasoning":"`+text+`","reasoning_details":[{"type":"reasoning.text","text":"`+text+`","format":"anthropic-claude-v1","index":0}]}`, "null")
	}
	switch slug {
	case "logprobs":
		return []peerEvent{
			{"", chatChunkWith(`{"index":0,"delta":{"role":"assistant","content":"Hello"},"logprobs":{"content":[` + logprob("Hello") + `],"refusal":null},"finish_reason":null}`)},
			{"", chatChunkWith(`{"index":0,"delta":{"content":" world"},"logprobs":{"content":[` + logprob(" world") + `],"refusal":null},"finish_reason":null}`)},
			{"", chatChunk(`{}`, `"stop"`)},
			{"", "[DONE]"},
		}
	case "reasoning-details":
		return []peerEvent{
			{"", detail("think key=" + value[:12])},
			{"", detail(value[12:])},
			{"", chatChunk(`{"content":"done"}`, "null")},
			{"", chatChunk(`{}`, `"stop"`)},
			{"", "[DONE]"},
		}
	case "chat-tool-truncated":
		return []peerEvent{
			{"", chatChunk(`{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"token\":\"`+value[:16]+`"}}]}`, "null")},
			{"", chatChunk(`{"tool_calls":[{"index":0,"function":{"arguments":"`+value[16:]+`"}}]}`, "null")},
			{"", chatChunk(`{}`, `"length"`)},
			{"", "[DONE]"},
		}
	case "anthropic-tool-truncated":
		return []peerEvent{
			messageStart,
			blockEdge("content_block_start", 0, `{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}`),
			blockDelta(0, "input_json_delta", "partial_json", `{\"token\": \"`+value[:20]),
			blockDelta(0, "input_json_delta", "partial_json", value[20:]),
			blockEdge("content_block_stop", 0, ""),
			{"ping", `{"type":"ping"}`},
			{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"max_tokens","stop_sequence":null},"usage":{"output_tokens":5}}`},
			{"message_stop", `{"type":"message_stop"}`},
		}
	case "responses-incomplete":
		return []peerEvent{
			{"response.created", `{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`},
			itemAdded,
			argumentsDelta("fc_1", 0, `{\"token\":\"`+value[:10]),
			argumentsDelta("fc_1", 0, value[10:]),
			{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","status":"incomplete","call_id":"call_1","name":"lookup","arguments":"{\"token\":\"` + value + `"}}`},
			{"response.incomplete", `{"type":"response.incomplete","response":{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`},
		}
	}
	return nil
}

// jsonNumberDocument reflects a numeric credential in a numeric position, where
// a word placeholder would make the JSON invalid, and in a string position,
// where it stays valid.
func jsonNumberDocument(slug, value string) string {
	switch slug {
	case "number":
		return `{"count":` + value + `}`
	case "string":
		return `{"s":"` + value + `"}`
	}
	return ""
}

// altEscape spells s for a JSON string, every other character as a \uXXXX
// escape and the rest literally; nested doubles the backslash for text carried
// inside another JSON string.
func altEscape(s string, nested bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i%2 == 0 {
			if nested {
				b.WriteString(`\`)
			}
			fmt.Fprintf(&b, `\u%04x`, s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// argDelta is one Responses function-call arguments delta carrying a raw
// fragment of the arguments JSON, escaped for the outer delta string.
func argDelta(item string, output int, fragment string) peerEvent {
	esc, _ := json.Marshal(fragment)
	return peerEvent{"response.function_call_arguments.delta", fmt.Sprintf(
		`{"type":"response.function_call_arguments.delta","item_id":"%s","output_index":%d,"delta":%s}`, item, output, esc)}
}

// writeNested returns a Responses tool call whose arguments carry the credential
// as a nested string value spelled with alternate escapes and as a nested
// object key, split across records.
func writeNested(w http.ResponseWriter, value string) {
	nested := altEscape(value, false)
	raw := `{"echo":"` + nested + `","` + nested + `":true}`
	cuts := []int{len(raw) / 3, 2 * len(raw) / 3}
	writeEvent(w, "response.created", `{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`)
	writeEvent(w, itemAdded.name, itemAdded.data)
	for _, fragment := range []string{raw[:cuts[0]], raw[cuts[0]:cuts[1]], raw[cuts[1]:]} {
		ev := argDelta("fc_1", 0, fragment)
		writeEvent(w, ev.name, ev.data)
	}
	full, _ := json.Marshal(`{"echo":"` + value + `","` + value + `":true}`)
	for _, ev := range []peerEvent{
		{"response.function_call_arguments.done", `{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":` + string(full) + `}`},
		{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"lookup","arguments":` + string(full) + `}}`},
		{"response.completed", `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
	} {
		writeEvent(w, ev.name, ev.data)
	}
}

// argumentText is a tool call's arguments JSON reflecting the credential with
// alternate escapes: beside an escaped quote, backslash and Unicode in a value
// and a key ("escaped"), or with one strict-policy breach.
func argumentText(kind, value string) string {
	v := altEscape(value, false)
	switch kind {
	case "escaped":
		return `{"note":"say \"` + v + `\" at C:\\ \u00e9","\"` + v + `\\":1}`
	case "collision":
		return `{"` + v + `":1,"` + projectionPlaceholder + `":2}`
	case "malformed":
		return `{"a":[1},"b":"` + v + `"}`
	case "unclosed":
		return `{"a":"` + v + `"`
	case "escape":
		return `{"a":"\q","b":"` + v + `"}`
	case "surrogate":
		return `{"a":"\ud800x","b":"` + v + `"}`
	}
	return ""
}

// argumentEvents streams one tool call whose arguments are text, cut into
// three deltas, in a family's protocol: Chat, Anthropic, or a Responses
// function_call or mcp_call, whose done events repeat the whole text.
func argumentEvents(family, text string) []peerEvent {
	var frags []string
	for i := 0; i < 3; i++ {
		frag, _ := json.Marshal(text[i*len(text)/3 : (i+1)*len(text)/3])
		frags = append(frags, string(frag))
	}
	var events []peerEvent
	switch family {
	case "chat":
		for i, frag := range frags {
			id := `"id":"call_1","type":"function","function":{"name":"lookup",`
			if i > 0 {
				id = `"function":{`
			}
			events = append(events, peerEvent{"", chatChunk(`{"tool_calls":[{"index":0,`+id+`"arguments":`+frag+`}}]}`, "null")})
		}
		return append(events, peerEvent{"", chatChunk(`{}`, `"tool_calls"`)}, peerEvent{"", "[DONE]"})
	case "anthropic":
		events = append(events, messageStart, blockEdge("content_block_start", 0, `{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}`))
		for _, frag := range frags {
			events = append(events, peerEvent{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":` + frag + `}}`})
		}
		return append(events, blockEdge("content_block_stop", 0, ""),
			peerEvent{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`}, peerEvent{"message_stop", `{"type":"message_stop"}`})
	}
	event := "response." + family + "_arguments"
	events = append(events, peerEvent{"response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"` + family + `","name":"lookup","arguments":""}}`})
	for _, frag := range frags {
		events = append(events, peerEvent{event + ".delta", `{"type":"` + event + `.delta","item_id":"fc_1","output_index":0,"delta":` + frag + `}`})
	}
	done, itemDone := argumentsDone(family, text)
	return append(events, done, itemDone,
		peerEvent{"response.completed", `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`})
}

// argumentsDone is the arguments done event and output_item.done event of a
// Responses function_call or mcp_call item fc_1, each repeating text whole.
func argumentsDone(family, text string) (peerEvent, peerEvent) {
	full, _ := json.Marshal(text)
	event := "response." + family + "_arguments.done"
	return peerEvent{event, `{"type":"` + event + `","item_id":"fc_1","output_index":0,"arguments":` + string(full) + `}`},
		peerEvent{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"` + family + `","name":"lookup","arguments":` + string(full) + `}}`}
}

// copyEvents streams the escaped arguments of a Responses function_call or
// mcp_call item whose complete copies are each spelled with other escapes
// ("respelled"), carry other arguments than the deltas ("done-differs",
// "item-differs"), repeat the done event ("duplicate-done"), follow the
// item's end ("late-done") or change its closing kind ("kind-differs", "kind-message").
func copyEvents(family, kind, value string) []peerEvent {
	events := argumentEvents(family, argumentText("escaped", value))
	head, done, itemDone, completed := events[:4:4], events[4], events[5], events[6]
	other, otherItem := argumentsDone(family, `{"note":"OFFENDING"}`)
	switch kind {
	case "respelled":
		done, _ = argumentsDone(family, `{"n\u006fte":"say \"`+value+`\" at C:\\ é","\"`+value+`\\":1}`)
		u := uEscape(value, false)
		_, itemDone = argumentsDone(family, `{"note":"say \u0022`+u+`\u0022 at C:\u005c \u00e9","\u0022`+u+`\u005c":1}`)
		return append(head, done, itemDone, completed)
	case "done-differs":
		return append(head, other, itemDone, completed)
	case "item-differs":
		return append(head, done, otherItem, completed)
	case "duplicate-done":
		return append(head, done, done, itemDone, completed)
	case "late-done":
		return append(head, done, itemDone, done, completed)
	case "kind-differs", "kind-message":
		closingKind := "message"
		if kind == "kind-differs" {
			closingKind = "function_call"
			if family == "function_call" {
				closingKind = "mcp_call"
			}
		}
		itemDone.data = strings.Replace(itemDone.data, `"type":"`+family+`"`, `"type":"`+closingKind+`"`, 1)
		return append(head, done, itemDone, completed)
	}
	return nil
}

// base32Fragment is the lowercase base32 spelling of s that the scrub derives
// for a value starting on a five-byte boundary.
func base32Fragment(s string) string {
	return strings.ToLower(base32.StdEncoding.EncodeToString([]byte(s)))[:8*len(s)/5]
}

// writeUnbounded answers a matched MCP route with one protected JSON document
// of small tokens, far past the proxy's cumulative document bound, and reports
// whether the proxy closed the connection before the peer wrote all of it.
func (peer *projectionPeer) writeUnbounded(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "application/json")
	filler := `,"` + strings.Repeat("a", 1<<10) + `"`
	_, err := io.WriteString(w, `{"jsonrpc":"2.0","id":null,"result":{"items":["`+value+`"`)
	for written := 0; err == nil && written < 64<<20; written += len(filler) {
		_, err = io.WriteString(w, filler)
	}
	if err == nil {
		_, err = io.WriteString(w, "]}}")
	}
	peer.closed <- err != nil
}

// responsesPartEvents drives the Responses content-part lifecycle: a valid
// message part, a refusal lane opened on an ended output_text part's index, and
// a delta for a part index that no part added.
func responsesPartEvents(slug, value string) []peerEvent {
	item := `"item_id":"msg_1","output_index":0,"content_index":0`
	msgItem := peerEvent{"response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`}
	addText := peerEvent{"response.content_part.added", `{"type":"response.content_part.added",` + item + `,"part":{"type":"output_text","text":""}}`}
	delta1 := peerEvent{"response.output_text.delta", `{"type":"response.output_text.delta",` + item + `,"delta":"secret: ` + value[:12] + `"}`}
	delta2 := peerEvent{"response.output_text.delta", `{"type":"response.output_text.delta",` + item + `,"delta":"` + value[12:] + `"}`}
	partDone := peerEvent{"response.content_part.done", `{"type":"response.content_part.done",` + item + `,"part":{"type":"output_text","text":""}}`}
	switch slug {
	case "valid":
		return []peerEvent{msgItem, addText, delta1, delta2, partDone,
			{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`},
			{"response.completed", `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}}
	case "refusal-after-text":
		return []peerEvent{msgItem, addText, delta1, delta2, partDone,
			{"response.refusal.delta", `{"type":"response.refusal.delta",` + item + `,"delta":"OFFENDING"}`}}
	case "unknown-part":
		return []peerEvent{msgItem,
			{"response.output_text.delta", `{"type":"response.output_text.delta",` + item + `,"delta":"OFFENDING"}`}}
	}
	return nil
}

// writeBroken sends one admitted chunk, whose value the proxy still holds,
// then ends the chunked body without its last chunk: by closing the TLS
// stream ("truncated") or by writing an invalid chunk ("protocol"). It then
// waits for the proxy to close the upstream connection.
func (peer *projectionPeer) writeBroken(w http.ResponseWriter, kind, value string) {
	writeEvent(w, "", chatChunk(`{"role":"assistant","content":"key=`+value[:8]+`"}`, "null"))
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		peer.closed <- false
		return
	}
	defer conn.Close()
	if kind == "protocol" {
		_, _ = conn.Write([]byte("zz\r\n"))
	} else if stream, ok := conn.(*tls.Conn); ok {
		_ = stream.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.Copy(io.Discard, buffered)
	var timeout net.Error
	peer.closed <- !(errors.As(err, &timeout) && timeout.Timeout())
}

func writeRaw(w http.ResponseWriter, text string) {
	_, _ = io.WriteString(w, text)
	w.(http.Flusher).Flush()
}

func writeEvent(w http.ResponseWriter, name, data string) {
	if name != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", name)
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	w.(http.Flusher).Flush()
}

// writeSplit sends one event in two HTTP chunks, cut inside its JSON.
func writeSplit(w http.ResponseWriter, name, data string) {
	cut := len(data) / 2
	if name != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", name)
	}
	_, _ = fmt.Fprintf(w, "data: %s", data[:cut])
	w.(http.Flusher).Flush()
	time.Sleep(2 * time.Millisecond)
	_, _ = fmt.Fprintf(w, "%s\n\n", data[cut:])
	w.(http.Flusher).Flush()
}

// uEscape spells each byte as a JSON \u escape; nested doubles the backslash
// for JSON text carried inside a JSON string.
func uEscape(s string, nested bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if nested {
			b.WriteString(`\`)
		}
		fmt.Fprintf(&b, `\u%04x`, s[i])
	}
	return b.String()
}

func chatChunk(delta, finish string) string {
	return `{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":` + delta + `,"finish_reason":` + finish + `}]}`
}

func writeChat(w http.ResponseWriter, value string, release <-chan struct{}) {
	writeEvent(w, "", chatChunk(`{"role":"assistant","content":"key=`+value[:8]+`"}`, "null"))
	<-release
	writeSplit(w, "", chatChunk(`{"content":"`+uEscape(value[8:12], false)+value[12:24]+`"}`, "null"))
	writeEvent(w, "", chatChunk(`{"content":"`+value[24:]+` end 😀"}`, "null"))
	writeEvent(w, "", chatChunk(`{"reasoning_content":"think `+value[:12]+`"}`, "null"))
	writeEvent(w, "", chatChunk(`{"reasoning_content":"`+value[12:]+`"}`, "null"))
	writeEvent(w, "", chatChunk(`{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"token\":\"`+value[:16]+`"}}]}`, "null"))
	writeSplit(w, "", chatChunk(`{"tool_calls":[{"index":0,"function":{"arguments":"`+uEscape(value[16:17], true)+value[17:32]+`"}}]}`, "null"))
	writeEvent(w, "", chatChunk(`{"tool_calls":[{"index":0,"function":{"arguments":"`+value[32:]+`\",\"`+uEscape(value[:2], true)+value[2:]+`\":1}"}}]}`, "null"))
	writeEvent(w, "", chatChunk(`{}`, `"tool_calls"`))
	writeEvent(w, "", "[DONE]")
}

func blockDelta(index int, kind, field, text string) peerEvent {
	return peerEvent{"content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"%s","%s":"%s"}}`, index, kind, field, text)}
}

func blockEdge(typ string, index int, block string) peerEvent {
	if block == "" {
		return peerEvent{typ, fmt.Sprintf(`{"type":"%s","index":%d}`, typ, index)}
	}
	return peerEvent{typ, fmt.Sprintf(`{"type":"%s","index":%d,"content_block":%s}`, typ, index, block)}
}

var messageStart = peerEvent{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[]}}`}

func writeMessages(w http.ResponseWriter, value string) {
	events := []peerEvent{
		messageStart,
		blockEdge("content_block_start", 0, `{"type":"text","text":""}`),
		blockDelta(0, "text_delta", "text", "secret: "+value[:8]),
	}
	for _, ev := range events {
		writeEvent(w, ev.name, ev.data)
	}
	split := blockDelta(0, "text_delta", "text", uEscape(value[8:10], false)+value[10:28])
	writeSplit(w, split.name, split.data)
	for _, ev := range []peerEvent{
		blockDelta(0, "text_delta", "text", value[28:]+"!"),
		blockEdge("content_block_stop", 0, ""),
		blockEdge("content_block_start", 1, `{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}`),
		blockDelta(1, "input_json_delta", "partial_json", `{\"token\": \"`+value[:20]),
		blockDelta(1, "input_json_delta", "partial_json", value[20:]+`\"}`),
		blockEdge("content_block_stop", 1, ""),
		blockEdge("content_block_start", 2, `{"type":"thinking","thinking":"","signature":""}`),
		blockDelta(2, "thinking_delta", "thinking", "plan "+value[:16]),
		blockDelta(2, "thinking_delta", "thinking", value[16:]),
		blockDelta(2, "signature_delta", "signature", "sig"),
		blockEdge("content_block_stop", 2, ""),
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}`},
		{"message_stop", `{"type":"message_stop"}`},
	} {
		writeEvent(w, ev.name, ev.data)
	}
}

var itemAdded = peerEvent{"response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"lookup","arguments":""}}`}

func argumentsDelta(item string, output int, text string) peerEvent {
	return peerEvent{"response.function_call_arguments.delta", fmt.Sprintf(`{"type":"response.function_call_arguments.delta","item_id":"%s","output_index":%d,"delta":"%s"}`, item, output, text)}
}

func writeResponses(w http.ResponseWriter, value string) {
	arguments := `{\"token\":\"` + value + `\"}`
	for _, ev := range []peerEvent{
		{"response.created", `{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`},
		itemAdded,
		argumentsDelta("fc_1", 0, `{\"token\":\"`+value[:10]),
	} {
		writeEvent(w, ev.name, ev.data)
	}
	split := argumentsDelta("fc_1", 0, value[10:40])
	writeSplit(w, split.name, split.data)
	for _, ev := range []peerEvent{
		argumentsDelta("fc_1", 0, value[40:]+`\"}`),
		{"response.function_call_arguments.done", `{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":"` + arguments + `"}`},
		{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"lookup","arguments":"` + arguments + `"}}`},
		{"response.completed", `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
	} {
		writeEvent(w, ev.name, ev.data)
	}
}

// jsonDocument is one protected application/json body: a valid document, or
// one that breaks the strict policy after a valid prefix.
func jsonDocument(slug, value string) string {
	switch slug {
	case "valid":
		return `{"__proto__":{"own":true},"café":"été 😀","token":"` + uEscape(value[:4], false) + value[4:] +
			`","` + value + `":{"nested":[1,2.5,null,true,"x"]}}`
	case "mismatched":
		return `{"a":[1},"b":"` + value + `"}`
	case "escape":
		return `{"a":"\q","b":"` + value + `"}`
	case "duplicate":
		return `{"a":1,"a":"` + value + `"}`
	case "collision":
		return `{"` + value + `":1,"` + projectionPlaceholder + `":2}`
	case "trailing":
		return `{"a":1}` + "\n" + `{"b":"` + value + `"}`
	}
	return ""
}

// identityEvents each break one protocol identity rule; the offending event
// carries a marker that must never reach the client.
func identityEvents(slug string) []peerEvent {
	switch slug {
	case "responses-after-terminal":
		return []peerEvent{
			itemAdded, argumentsDelta("fc_1", 0, "{}"),
			{"response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","arguments":"{}"}}`},
			{"response.completed", `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
			argumentsDelta("fc_2", 1, "OFFENDING"),
		}
	case "responses-output-conflict":
		return []peerEvent{itemAdded, argumentsDelta("fc_1", 1, "OFFENDING")}
	case "responses-unknown-item":
		return []peerEvent{argumentsDelta("fc_9", 0, "OFFENDING")}
	case "anthropic-stop-before-start":
		return []peerEvent{messageStart, blockEdge("content_block_stop", 0, ""), blockDelta(0, "text_delta", "text", "OFFENDING")}
	case "anthropic-delta-without-start":
		return []peerEvent{messageStart, blockDelta(2, "text_delta", "text", "OFFENDING")}
	case "anthropic-wrong-delta-type":
		return []peerEvent{messageStart, blockEdge("content_block_start", 0, `{"type":"text","text":""}`), blockDelta(0, "input_json_delta", "partial_json", "OFFENDING")}
	case "chat-tool-id-conflict":
		return []peerEvent{
			{"", chatChunk(`{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{"}}]}`, "null")},
			{"", chatChunk(`{"tool_calls":[{"index":0,"id":"call_2","function":{"arguments":"OFFENDING"}}]}`, "null")},
		}
	case "chat-tool-without-id":
		return []peerEvent{{"", chatChunk(`{"tool_calls":[{"index":0,"function":{"arguments":"OFFENDING"}}]}`, "null")}}
	case "protocol-switch":
		return []peerEvent{{"", chatChunk(`{"content":"ok"}`, "null")}, itemAdded, argumentsDelta("fc_1", 0, "OFFENDING")}
	}
	return nil
}

// boundsEvents are events under the wire cap that are too deep, hold too many
// values or are too large to project, and controls just within the bounds.
func boundsEvents(slug string) []peerEvent {
	nest := func(depth int) string { return strings.Repeat("[", depth) + strings.Repeat("]", depth) }
	rpc := func(result string) peerEvent {
		return peerEvent{"message", `{"jsonrpc":"2.0","id":1,"result":` + result + `}`}
	}
	switch slug {
	case "deep":
		return []peerEvent{{"", `{"error":{"x":` + nest(200) + `}}`}}
	case "values":
		return []peerEvent{{"", `{"error":{"v":[` + strings.Repeat("0,", 70000) + `0]}}`}}
	case "large":
		return []peerEvent{{"", chatChunk(`{"content":"`+strings.Repeat("a", 5<<20)+`"}`, "null")}}
	case "deep-within":
		return []peerEvent{rpc(`{"x":` + nest(40) + `}`)}
	case "large-within":
		return []peerEvent{rpc(`{"text":"` + strings.Repeat("a", 1<<20) + `"}`)}
	}
	return nil
}

func projectionUpstreamCert(t *testing.T, dir string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: projectionHost},
		DNSNames:              []string{projectionHost},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(dir, "upstream.crt")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

// connectTunnel is the upstream forward proxy: it accepts CONNECT for the
// declared host only and splices it to the upstream listener.
func connectTunnel(t *testing.T, target string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != projectionHost+":443" {
			http.Error(w, "unexpected tunnel", http.StatusBadRequest)
			return
		}
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write errors end the splice; the fixture has no caller to tell.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(upstream, buffered)
			if tcp, ok := upstream.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
		_, _ = io.Copy(conn, upstream)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}
