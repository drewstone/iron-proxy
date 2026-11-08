package secrets

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A protected response answers a request that redeemed a canonical secret.
// Its body is admitted by media type before any byte of it is forwarded:
//
//   - text/event-stream is parsed event by event. Comments become bare
//     heartbeats; event and id pass the scrub, and retry is projected and
//     kept only while it stays a number. Each data payload must be one
//     strict JSON object of a supported stream: OpenAI Chat Completions
//     chunks, OpenAI Responses events, Anthropic Messages events, a JSON-RPC
//     message or an error envelope. The text lanes of the model streams
//     (content, refusal and reasoning text, tool and function call arguments)
//     are projected as decoded text across events, so a value split across
//     delta records is replaced as a whole, using only the pairs this request
//     captured. Each stream must follow its protocol's identities: blocks and
//     items start before their deltas, tool calls keep their ids, and nothing
//     follows an ended block, item, choice or stream. Any other payload, field,
//     delta or transition is refused.
//   - application/json and +json are one strict JSON value, passed on token
//     by token under the same policy as an event payload (semantic_json.go).
//     The strings at one place of the document, array positions aside, are
//     one lane: a value split across them, as across the chunks of a model
//     stream sent as a JSON array, is refused before its second part.
//   - Record streams (NDJSON, JSON Lines, JSON text sequences) and a body
//     with no media type are refused with a 502; a body proved empty passes.
//   - Every other type keeps the byte scrub of an ordinary response.
//
// A refusal, or any failure reading a protected body, ends it with
// ErrResponseRefused and drops what the scrub holds, so the client never
// receives a held fragment or a prefix that looks complete.

// ErrResponseRefused ends a protected response whose next bytes cannot be
// projected. The proxy aborts the connection rather than finishing the body.
var ErrResponseRefused = errors.New("protected response refused")

// These bound the state one protected response holds; nothing configures
// them, and each is checked before the state it bounds grows.
const (
	// maxProtectedRecord bounds one server-sent event, one unterminated
	// line, one JSON document token and the object keys a payload keeps.
	maxProtectedRecord = 4 << 20
	// maxProtectedDepth bounds JSON nesting.
	maxProtectedDepth = 64
	// maxProtectedValues bounds the values one event payload is parsed into.
	maxProtectedValues = 1 << 16
	// maxProtectedLanes bounds the text lanes one stream may open.
	maxProtectedLanes = 256
	// maxProtectedFacts bounds the protocol identities one stream declares.
	maxProtectedFacts = 1024
	// maxLaneMeta bounds each identity string a lane or fact keeps.
	maxLaneMeta = 256
)

// protectedBody returns the reader that projects a protected body and the
// mode it was admitted in, or a nil reader and the refused mode.
func protectedBody(resp *http.Response, stream io.Reader, closer io.Closer, scrub *scrubber) (*scrubReader, string) {
	values := resp.Header.Values("Content-Type")
	if len(values) == 0 {
		var probe [1]byte
		if n, err := io.ReadFull(stream, probe[:]); n == 0 && errors.Is(err, io.EOF) {
			return newScrubReader(stream, closer, scrub), "empty"
		}
		return nil, "untyped"
	}
	media, _, err := mime.ParseMediaType(values[0])
	if len(values) != 1 || err != nil {
		return nil, "invalid_type"
	}
	switch {
	case media == "text/event-stream":
		sse := &sseProjector{scrub: scrub, lanes: map[string]*lane{}, facts: map[string]string{}, split: newSplitFence(scrub)}
		return &scrubReader{src: stream, closer: closer, project: sse.project, strict: true, chunk: make([]byte, 32<<10)}, "sse"
	case recordStream(media):
		return nil, "record_stream"
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		// Validate the input document, project it, then validate the projected
		// output is still one JSON value: a token the scrub turned invalid, such
		// as a numeric credential projected to a word placeholder, is refused
		// rather than completed as malformed JSON. Each stage holds one token.
		project := newScrubReader(newJSONDocReader(stream, scrub), nil, scrub)
		project.strict = true
		reader := &scrubReader{src: newJSONDocReader(project, nil), closer: closer, project: passBytes, strict: true, chunk: make([]byte, 32<<10)}
		return reader, "json"
	}
	return newScrubReader(stream, closer, scrub), "bytes"
}

// passBytes forwards already-projected, already-validated bytes unchanged; it
// is the projection of the outer reader that only revalidates a JSON document.
func passBytes(dst, data []byte, final bool) ([]byte, int, error) {
	return append(dst, data...), 0, nil
}

func recordStream(media string) bool {
	for _, marker := range []string{"ndjson", "jsonl", "jsonlines", "json-seq", "stream+json", "json-stream"} {
		if strings.Contains(media, marker) {
			return true
		}
	}
	return false
}

// lane is one stream of text a model sends in pieces. It holds only the
// decoded suffix that may still begin a captured value.
type lane struct {
	key, group, field, bind string
	held                    []byte
	closed                  bool
	named                   bool
	// nested marks a lane whose text is itself JSON (a tool call's arguments),
	// held whole and projected under the strict policy once it ends; when bind
	// is set, that projected value's identity is declared as the bind fact.
	nested bool
	// flush rebuilds a record that carries only text in this lane, with the
	// identity of the last record that continued it.
	flush func(text string) (event, data string)
}

// lanePart is one string of a record that continues a lane.
type lanePart struct {
	key, group, field, bind string
	value                   *jsonValue
	nested                  bool
	flush                   func(text string) (event, data string)
}

// recordPlan is what one record does: the lane parts it continues, the
// complete arguments it repeats with the fact they bind, the lanes it ends
// (closes), the groups it ends for good, whether it ends the stream and
// whether it says the stream was cut off at its length limit.
type recordPlan struct {
	parts     []lanePart
	arguments []*jsonValue
	bind      string
	closes    func(*lane) bool
	ended     []string
	terminal  bool
	truncated bool
}

func closeAll(*lane) bool { return true }

func endGroups(groups ...string) recordPlan {
	return recordPlan{closes: func(l *lane) bool { return slices.Contains(groups, l.group) }, ended: groups}
}

type sseEvent struct {
	fields                   bool
	name, id, retry          string
	hasName, hasID, hasRetry bool
	data                     []string
}

// sseProjector projects one protected server-sent event stream. Its lanes
// and facts are this response's alone.
type sseProjector struct {
	scrub *scrubber
	lanes map[string]*lane
	order []string
	// facts are the identities the stream has declared: its protocol,
	// started blocks and items, tool call ids and ended groups.
	facts              map[string]string
	terminal, doneSeen bool
	// size is the open event's bytes; argBytes those held by argument lanes.
	size, argBytes int
	event          sseEvent
	// searched is how much of the unterminated line held from the last read
	// was already searched for its end.
	searched int
	// truncating is set while a record that says the stream was cut off ends
	// its lanes. unfinished are argument lanes that ended without one JSON
	// value before the stream said so; the records from their end on wait in
	// deferred until it does, or the stream is refused.
	truncating bool
	unfinished []*lane
	deferred   []byte
	// split fences values that are not one lane, such as log probabilities.
	split *splitFence
}

// declare records an identity fact; a different value for it is a conflict.
func (p *sseProjector) declare(key, value string) error {
	if old, ok := p.facts[key]; ok {
		if old != value {
			return ErrResponseRefused
		}
		return nil
	}
	if len(p.facts) >= maxProtectedFacts || len(key)+len(value) > 2*maxLaneMeta {
		return ErrResponseRefused
	}
	p.facts[key] = value
	return nil
}

// start declares a fact that must be new, such as a block or item start.
func (p *sseProjector) start(key, value string) error {
	if _, ok := p.facts[key]; ok {
		return ErrResponseRefused
	}
	return p.declare(key, value)
}

func (p *sseProjector) known(key string) bool {
	_, ok := p.facts[key]
	return ok
}

func (p *sseProjector) project(dst, data []byte, final bool) ([]byte, int, error) {
	// The held line was searched already; searching it again on every read
	// would make a long line arriving in small reads quadratic.
	start, from := 0, p.searched
	searched := len(data)
	for {
		at := bytes.IndexAny(data[from:], "\r\n")
		if at < 0 {
			break
		}
		end := from + at
		next := end + 1
		if data[end] == '\r' {
			if next == len(data) && !final {
				searched = end
				break
			}
			if next < len(data) && data[next] == '\n' {
				next++
			}
		}
		var err error
		if dst, err = p.line(dst, data[start:end]); err != nil {
			return dst, 0, err
		}
		start, from = next, next
	}
	rest := len(data) - start
	if p.size+rest > maxProtectedRecord {
		return dst, 0, ErrResponseRefused
	}
	if !final {
		p.searched = searched - start
		return dst, rest, nil
	}
	// A model stream must reach its protocol's completion before a clean EOF;
	// otherwise its held lanes are dropped and the response refused, so a
	// partial prefix is never flushed as a finished stream. Protocols whose
	// own completion is a clean EOF (JSON-RPC, a lone error envelope, or a
	// stream that opened nothing) end normally.
	if p.requiresCompletion() && !p.terminal {
		return dst, 0, ErrResponseRefused
	}
	// No reader dispatches an unterminated event, so it is dropped; every
	// lane still open sends what it holds.
	dst, err := p.flush(dst, closeAll)
	return dst, 0, err
}

// requiresCompletion reports a declared model stream whose protocol ends only
// with an explicit terminal event, not a bare transport EOF.
func (p *sseProjector) requiresCompletion() bool {
	switch p.facts["protocol"] {
	case "chat", "anthropic", "responses":
		return true
	}
	return false
}

func (p *sseProjector) line(dst, line []byte) ([]byte, error) {
	if len(line) > 0 && line[0] == ':' {
		// A comment is a heartbeat to a reader; its text is not forwarded.
		return append(dst, ":\n"...), nil
	}
	p.size += len(line) + 1
	if p.size > maxProtectedRecord || !utf8.Valid(line) {
		return dst, ErrResponseRefused
	}
	if len(line) == 0 {
		return p.dispatch(dst)
	}
	name, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	ev := &p.event
	ev.fields = true
	switch string(name) {
	case "data":
		ev.data = append(ev.data, string(value))
	case "event":
		ev.name, ev.hasName = string(value), true
	case "id":
		ev.id, ev.hasID = string(value), true
	case "retry":
		// A retry is projected like every field; one that the projection
		// leaves no longer a number is refused rather than sent unprojected.
		projected := p.scrub.text(string(value))
		if projected == "" || strings.Trim(projected, "0123456789") != "" {
			return dst, ErrResponseRefused
		}
		ev.retry, ev.hasRetry = projected, true
	default:
		return dst, ErrResponseRefused
	}
	return dst, nil
}

func (p *sseProjector) dispatch(dst []byte) ([]byte, error) {
	start := len(dst)
	dst, err := p.dispatchEvent(dst)
	if err != nil || len(p.unfinished) == 0 {
		return dst, err
	}
	// Held until the stream says whether the unfinished arguments were cut
	// off; comments and empty events, which carry nothing, still pass.
	p.deferred = append(p.deferred, dst[start:]...)
	if len(p.deferred) > maxProtectedRecord {
		return dst[:start], ErrResponseRefused
	}
	return dst[:start], nil
}

func (p *sseProjector) dispatchEvent(dst []byte) ([]byte, error) {
	ev := p.event
	p.event, p.size = sseEvent{}, 0
	if !ev.fields {
		return append(dst, '\n'), nil
	}
	data := strings.Join(ev.data, "\n")
	if data != "" {
		// Nothing follows the end of a stream but one [DONE].
		if p.terminal && (data != "[DONE]" || p.doneSeen) {
			return dst, ErrResponseRefused
		}
		var before []byte
		var err error
		if data == "[DONE]" {
			if len(p.unfinished) > 0 {
				return dst, ErrResponseRefused
			}
			p.terminal, p.doneSeen = true, true
			before, err = p.flush(nil, closeAll)
		} else {
			before, data, err = p.record(ev, data)
		}
		if err != nil {
			return dst, err
		}
		dst = append(dst, before...)
	}
	return p.write(dst, ev, data), nil
}

func (p *sseProjector) write(dst []byte, ev sseEvent, data string) []byte {
	field := func(name, value string) {
		dst = append(append(append(append(dst, name...), ": "...), value...), '\n')
	}
	if ev.hasName {
		field("event", p.scrub.text(ev.name))
	}
	if ev.hasID {
		field("id", p.scrub.text(ev.id))
	}
	if ev.hasRetry {
		field("retry", ev.retry)
	}
	if len(ev.data) > 0 {
		for _, line := range strings.Split(data, "\n") {
			field("data", line)
		}
	}
	return append(dst, '\n')
}

// record projects one JSON payload. It returns the records that must precede
// it, which send what the lanes it ends still hold, and the payload to send.
func (p *sseProjector) record(ev sseEvent, data string) ([]byte, string, error) {
	doc, err := parseJSON([]byte(data), p.scrub, nil)
	if err != nil {
		return nil, "", err
	}
	plan, err := p.classify(doc, ev)
	if err != nil {
		return nil, "", err
	}
	p.truncating = plan.truncated
	defer func() { p.truncating = false }()
	// A record that says the stream was cut off releases the arguments that
	// ended unfinished, with the flat scrub, and the records that waited.
	var released []byte
	if plan.truncated && len(p.unfinished) > 0 {
		for _, l := range p.unfinished {
			out, _ := p.scrub.scan(nil, l.held, true)
			p.argBytes -= len(l.held)
			l.held = nil
			if released, err = p.writeLane(released, l, out); err != nil {
				return nil, "", err
			}
		}
		released = append(released, p.deferred...)
		p.unfinished, p.deferred = nil, nil
	}
	type replacement struct {
		value *jsonValue
		text  string
	}
	var replaced []replacement
	for i, part := range plan.parts {
		for _, earlier := range plan.parts[:i] {
			if earlier.key == part.key {
				return nil, "", ErrResponseRefused
			}
		}
		l := p.lanes[part.key]
		if l == nil {
			// A lane opens only in a group that has not ended.
			if p.known("ended:"+part.group) || len(p.lanes) >= maxProtectedLanes {
				return nil, "", ErrResponseRefused
			}
			l = &lane{key: part.key, group: part.group, field: part.field, bind: part.bind, nested: part.nested}
			p.lanes[part.key] = l
			p.order = append(p.order, part.key)
		}
		if l.group != part.group || l.field != part.field {
			return nil, "", ErrResponseRefused
		}
		if l.closed {
			if part.value.str != "" {
				return nil, "", ErrResponseRefused
			}
			continue
		}
		l.flush, l.named = part.flush, ev.hasName
		final := plan.closes != nil && plan.closes(l)
		text := append(l.held, part.value.str...)
		out, held, err := p.projectLane(l, text, final)
		if err != nil {
			return nil, "", err
		}
		if held < len(text) {
			text = append([]byte(nil), text[len(text)-held:]...)
		}
		l.held, l.closed = text, final
		replaced = append(replaced, replacement{value: part.value, text: string(out)})
	}
	// A record with complete arguments continues no lane, so its replacements
	// stay in record order. Each copy and the item's argument lane declare one
	// decoded identity as the bind fact, so a differing copy refuses unsent.
	copyUnfinished := false
	for _, v := range plan.arguments {
		out, identity, err := projectArguments(p.scrub, []byte(v.str))
		switch {
		case err != nil && (p.truncating || len(p.unfinished) > 0 || p.facts["protocol"] == "responses"):
			// A copy of arguments that were cut off: the flat scrub, and
			// held with them until the stream says so.
			out, _ = p.scrub.scan(nil, []byte(v.str), true)
			copyUnfinished, err = !p.truncating, nil
		case err == nil:
			err = p.declare(plan.bind, identity)
		}
		if err != nil {
			return nil, "", err
		}
		replaced = append(replaced, replacement{value: v, text: string(out)})
	}
	var before []byte
	if plan.closes != nil {
		if before, err = p.flush(nil, plan.closes); err != nil {
			return nil, "", err
		}
	}
	// An unfinished copy is admitted only beside unfinished lane arguments,
	// which hold it until the stream says it was cut off.
	if copyUnfinished && len(p.unfinished) == 0 {
		return nil, "", ErrResponseRefused
	}
	for _, group := range plan.ended {
		delete(p.facts, "arguments:"+group) // An ended group keeps only its end.
		if err := p.declare("ended:"+group, ""); err != nil {
			return nil, "", err
		}
	}
	p.terminal = p.terminal || plan.terminal
	record, last := []byte(nil), 0
	for _, r := range replaced {
		record = appendJSONString(append(record, data[last:r.value.start]...), r.text)
		last = r.value.end
	}
	final, err := p.finish(append(record, data[last:]...), data)
	if err != nil {
		return nil, "", err
	}
	return append(released, before...), final, nil
}

// flush ends the open lanes closes selects, in the order they opened, and
// writes a record for each that still held text.
func (p *sseProjector) flush(dst []byte, closes func(*lane) bool) ([]byte, error) {
	for _, key := range p.order {
		l := p.lanes[key]
		if l.closed || !closes(l) {
			continue
		}
		out, _, err := p.projectLane(l, l.held, true)
		if errors.Is(err, errUnfinished) {
			l.closed = true
			p.unfinished = append(p.unfinished, l)
			continue
		}
		if err != nil {
			return dst, err
		}
		l.held, l.closed = nil, true
		if dst, err = p.writeLane(dst, l, out); err != nil {
			return dst, err
		}
	}
	return dst, nil
}

// writeLane writes a record that carries the rest of an ended lane's text.
func (p *sseProjector) writeLane(dst []byte, l *lane, out []byte) ([]byte, error) {
	if len(out) == 0 {
		return dst, nil
	}
	name, data := l.flush(string(out))
	record, err := p.finish([]byte(data), "")
	if err != nil {
		return dst, err
	}
	ev := sseEvent{fields: true, data: []string{record}}
	if l.named && name != "" {
		ev.name, ev.hasName = name, true
	}
	return p.write(dst, ev, record), nil
}

var anthropicEvents = map[string]bool{
	"message_start": true, "message_delta": true, "message_stop": true, "ping": true,
	"content_block_start": true, "content_block_delta": true, "content_block_stop": true,
}

// classify names the lanes of one record, refusing a payload of no supported
// stream, a stream that changes protocol, an unknown text field and an
// ambiguous, missing or conflicting identity.
func (p *sseProjector) classify(doc jsonDoc, ev sseEvent) (recordPlan, error) {
	if doc[0].kind != '{' {
		return recordPlan{}, ErrResponseRefused
	}
	typ, _ := doc.get("type").text()
	if typ != "" && ev.hasName && ev.name != "" && ev.name != typ {
		return recordPlan{}, ErrResponseRefused
	}
	protocol := ""
	switch {
	case typ == "error":
		return recordPlan{closes: closeAll, terminal: true}, nil
	case doc.get("choices") != nil:
		protocol = "chat"
	case anthropicEvents[typ]:
		protocol = "anthropic"
	case strings.HasPrefix(typ, "response."):
		protocol = "responses"
	case typ == "" && doc.get("jsonrpc") != nil:
		return recordPlan{}, p.declare("protocol", "jsonrpc")
	case typ == "" && doc.get("error") != nil:
		return recordPlan{closes: closeAll, terminal: true}, nil
	default:
		return recordPlan{}, ErrResponseRefused
	}
	if err := p.declare("protocol", protocol); err != nil {
		return recordPlan{}, err
	}
	switch protocol {
	case "chat":
		return p.chatPlan(doc)
	case "anthropic":
		return p.anthropicPlan(doc, typ)
	}
	return p.responsesPlan(doc, typ)
}

var chatReasoning = map[string]bool{"reasoning_content": true, "reasoning": true, "reasoning_text": true}

// chatPlan reads an OpenAI Chat Completions chunk. A lane is the choice's
// index with its content, refusal, one reasoning field, a tool call's index
// or the legacy function call. A tool call's arguments follow its id, which
// with its name never changes.
func (p *sseProjector) chatPlan(doc jsonDoc) (recordPlan, error) {
	var plan recordPlan
	choices := map[int]int{}
	tools := map[[2]int]int{}
	descriptors := map[[2]int][2]string{}
	for i := range doc {
		v, path := &doc[i], doc.path(i)
		switch {
		case pathIs(path, "choices", -1, "index"):
			if n, ok := v.index(); ok {
				choices[path[1].(int)] = n
			}
		case pathIs(path, "choices", -1, "delta", "tool_calls", -1, "index"):
			if n, ok := v.index(); ok {
				tools[[2]int{path[1].(int), path[4].(int)}] = n
			}
		case pathIs(path, "choices", -1, "delta", "tool_calls", -1, "id"), pathIs(path, "choices", -1, "delta", "tool_calls", -1, "function", "name"):
			at := [2]int{path[1].(int), path[4].(int)}
			d := descriptors[at]
			d[len(path)-6] = v.str
			descriptors[at] = d
		}
	}
	for at, d := range descriptors {
		choice, okChoice := choices[at[0]]
		tool, okTool := tools[at]
		if !okChoice || !okTool {
			return plan, ErrResponseRefused
		}
		call := strconv.Itoa(choice) + ":" + strconv.Itoa(tool)
		if d[0] != "" {
			if err := p.declare("chat.tool:"+call, d[0]); err != nil {
				return plan, err
			}
		}
		if d[1] != "" {
			if err := p.declare("chat.name:"+call, d[1]); err != nil {
				return plan, err
			}
		}
	}
	head := ""
	for _, name := range []string{"id", "object", "model"} {
		if s, ok := doc.get(name).text(); ok {
			head += quote(name) + ":" + quote(s) + ","
		}
	}
	if n, ok := doc.get("created").index(); ok {
		head += `"created":` + strconv.Itoa(n) + ","
	}
	var finished []string
	reasoning := map[int]string{}
	for i := range doc {
		v, path := &doc[i], doc.path(i)
		if v.kind != '"' || len(path) < 3 || !pathIn(path, "choices", -1) {
			continue
		}
		c := path[1].(int)
		choice, ok := choices[c]
		if !ok {
			return plan, ErrResponseRefused
		}
		group := "chat:" + strconv.Itoa(choice)
		flush := func(delta func(string) string) func(string) (string, string) {
			return func(text string) (string, string) {
				return "", "{" + head + `"choices":[{"index":` + strconv.Itoa(choice) + `,"delta":` + delta(text) + `,"finish_reason":null}]}`
			}
		}
		field, _ := path[len(path)-1].(string)
		switch {
		case pathIs(path, "choices", c, "finish_reason"):
			finished = append(finished, group)
			plan.truncated = plan.truncated || v.str == "length"
		case pathIn(path, "choices", c, "logprobs"):
			// Log probabilities repeat the content a token at a time, with
			// each token's bytes as numbers the scrub cannot read: a held value
			// in one token, or split across tokens of one place, is refused.
			if p.scrub.text(v.str) != v.str {
				return plan, ErrResponseRefused
			}
			if err := p.split.next(func() string { return group + ":" + shapeOf(path[2:]) }, v.str); err != nil {
				return plan, err
			}
		case pathIs(path, "choices", c, "delta", "reasoning_details", -1, "text"), pathIs(path, "choices", c, "delta", "reasoning_details", -1, "summary"):
			// OpenRouter streams reasoning as details, each continued by its
			// index; the text or summary of one index is a lane.
			at := path[4].(int)
			detail, ok := doc.get("choices", c, "delta", "reasoning_details", at, "index").index()
			if !ok {
				detail = at
			}
			kind, _ := doc.get("choices", c, "delta", "reasoning_details", at, "type").text()
			plan.parts = append(plan.parts, lanePart{key: group + ":details:" + strconv.Itoa(detail) + ":" + field, group: group, field: field, value: v,
				flush: flush(func(text string) string {
					return `{"reasoning_details":[{"type":` + quote(kind) + `,"index":` + strconv.Itoa(detail) + "," + quote(field) + ":" + quote(text) + "}]}"
				})})
		case pathIn(path, "choices", c, "delta", "reasoning_details"):
			// The type, format, id, signature and encrypted data of a detail
			// are complete values; the record scrub covers them.
		case pathIs(path, "choices", c, "native_finish_reason"), pathIs(path, "choices", c, "stop_reason"),
			pathIs(path, "choices", c, "delta", "role"),
			pathIs(path, "choices", c, "delta", "tool_calls", -1, "id"),
			pathIs(path, "choices", c, "delta", "tool_calls", -1, "type"),
			pathIs(path, "choices", c, "delta", "tool_calls", -1, "function", "name"),
			pathIs(path, "choices", c, "delta", "function_call", "name"):
			// Complete values; the record scrub covers them.
		case len(path) == 4 && pathIn(path, "choices", c, "delta") && (field == "content" || field == "refusal" || chatReasoning[field]):
			name := field
			if chatReasoning[field] {
				if earlier, seen := reasoning[c]; seen && earlier != field {
					return plan, ErrResponseRefused
				}
				reasoning[c], name = field, "thinking"
			}
			plan.parts = append(plan.parts, lanePart{key: group + ":" + name, group: group, field: field, value: v,
				flush: flush(func(text string) string { return "{" + quote(field) + ":" + quote(text) + "}" })})
		case pathIs(path, "choices", c, "delta", "tool_calls", -1, "function", "arguments"):
			tool, ok := tools[[2]int{c, path[4].(int)}]
			if !ok || !p.known("chat.tool:"+strconv.Itoa(choice)+":"+strconv.Itoa(tool)) {
				return plan, ErrResponseRefused
			}
			plan.parts = append(plan.parts, lanePart{key: group + ":tool:" + strconv.Itoa(tool), group: group, field: field, value: v, nested: true,
				flush: flush(func(text string) string {
					return `{"tool_calls":[{"index":` + strconv.Itoa(tool) + `,"function":{"arguments":` + quote(text) + "}}]}"
				})})
		case pathIs(path, "choices", c, "delta", "function_call", "arguments"):
			plan.parts = append(plan.parts, lanePart{key: group + ":function_call", group: group, field: field, value: v, nested: true,
				flush: flush(func(text string) string { return `{"function_call":{"arguments":` + quote(text) + "}}" })})
		default:
			return plan, ErrResponseRefused
		}
	}
	if len(finished) > 0 {
		ended := endGroups(finished...)
		plan.closes, plan.ended = ended.closes, ended.ended
	}
	return plan, nil
}

var anthropicDeltas = map[string]string{"text": "text_delta", "partial_json": "input_json_delta", "thinking": "thinking_delta", "signature": "signature_delta"}

// anthropicBlockDeltas lists the deltas each content block type carries.
var anthropicBlockDeltas = map[string][]string{
	"text":            {"text_delta", "citations_delta"},
	"thinking":        {"thinking_delta", "signature_delta"},
	"tool_use":        {"input_json_delta"},
	"server_tool_use": {"input_json_delta"},
}

// anthropicPlan reads an Anthropic Messages event. A message starts before
// its blocks; a block starts once, carries only the deltas of its type, and
// stops once; no block starts after the message delta. A lane is a block's
// index with its text, thinking, signature or partial input JSON.
func (p *sseProjector) anthropicPlan(doc jsonDoc, typ string) (recordPlan, error) {
	var plan recordPlan
	switch typ {
	case "message_start":
		return plan, p.start("anthropic.message", "")
	case "ping":
		return plan, nil
	}
	if !p.known("anthropic.message") {
		return plan, ErrResponseRefused
	}
	// Tool input that ended unfinished is admitted only when the next event
	// says the message stopped at its token limit.
	stop, _ := doc.get("delta", "stop_reason").text()
	cutOff := stop == "max_tokens" || stop == "model_context_window_exceeded"
	if len(p.unfinished) > 0 && (typ != "message_delta" || !cutOff) {
		return plan, ErrResponseRefused
	}
	switch typ {
	case "message_delta":
		plan.closes, plan.truncated = closeAll, cutOff
		return plan, p.declare("anthropic.ended", "")
	case "message_stop":
		plan.closes, plan.terminal = closeAll, true
		return plan, nil
	}
	index, ok := doc.get("index").index()
	if !ok {
		return plan, ErrResponseRefused
	}
	group := "anthropic:" + strconv.Itoa(index)
	block, ended := "anthropic.block:"+strconv.Itoa(index), p.known("ended:"+group)
	kind, started := p.facts[block]
	deltaType, _ := doc.get("delta", "type").text()
	switch typ {
	case "content_block_start":
		kind, _ = doc.get("content_block", "type").text()
		if kind == "" || p.known("anthropic.ended") {
			return plan, ErrResponseRefused
		}
		if err := p.start(block, kind); err != nil {
			return plan, err
		}
	case "content_block_stop":
		if !started || ended {
			return plan, ErrResponseRefused
		}
		return endGroups(group), nil
	default:
		if !started || ended || !slices.Contains(anthropicBlockDeltas[kind], deltaType) {
			return plan, ErrResponseRefused
		}
	}
	container := "delta"
	if typ == "content_block_start" {
		container = "content_block"
	}
	for i := range doc {
		v, path := &doc[i], doc.path(i)
		if v.kind != '"' || len(path) < 2 || !pathIn(path, container) {
			continue
		}
		field, _ := path[1].(string)
		fieldDelta, known := anthropicDeltas[field]
		lanePath := len(path) == 2 && known
		switch {
		case lanePath && typ == "content_block_delta" && fieldDelta == deltaType,
			lanePath && typ == "content_block_start" && field == kind:
			plan.parts = append(plan.parts, lanePart{key: group + ":" + field, group: group, field: field, value: v, nested: field == "partial_json",
				flush: func(text string) (string, string) {
					return "content_block_delta", `{"type":"content_block_delta","index":` + strconv.Itoa(index) +
						`,"delta":{"type":"` + fieldDelta + `",` + quote(field) + ":" + quote(text) + "}}"
				}})
		case typ == "content_block_start", pathIs(path, "delta", "type"), pathIn(path, "delta", "citation"):
			// Complete values; the record scrub covers them.
		default:
			return plan, ErrResponseRefused
		}
	}
	return plan, nil
}

// responseLanes maps each OpenAI Responses delta event to the index that,
// with its item and output index, names its lane ("" for none).
var responseLanes = map[string]string{
	"response.output_text.delta":                "content_index",
	"response.refusal.delta":                    "content_index",
	"response.reasoning_text.delta":             "content_index",
	"response.reasoning_summary_text.delta":     "summary_index",
	"response.function_call_arguments.delta":    "",
	"response.custom_tool_call_input.delta":     "",
	"response.mcp_call_arguments.delta":         "",
	"response.code_interpreter_call_code.delta": "",
}

// nestedArgumentDelta lists the Responses deltas whose text is a tool call's
// JSON arguments, projected as nested JSON. A custom tool's input and code
// interpreter code are not JSON, so they keep the flat scrub.
var nestedArgumentDelta = map[string]bool{
	"response.function_call_arguments.delta": true,
	"response.mcp_call_arguments.delta":      true,
}

func responseLane(typ, item string, output, sub int) lanePart {
	key := typ + "\x00" + item + "\x00" + strconv.Itoa(output)
	head := `{"type":` + quote(typ) + `,"item_id":` + quote(item) + `,"output_index":` + strconv.Itoa(output)
	if name := responseLanes[typ]; name != "" {
		key += "\x00" + strconv.Itoa(sub)
		head += "," + quote(name) + ":" + strconv.Itoa(sub)
	}
	return lanePart{key: key, group: "response:" + item, field: typ, bind: "arguments:response:" + item, nested: nestedArgumentDelta[typ], flush: func(text string) (string, string) {
		return typ, head + `,"delta":` + quote(text) + "}"
	}}
}

// partKey names the content or summary part of an item at a sub-index. Its
// kind, its start and its end are facts a later delta for that index must
// agree with, so an ended part cannot be reopened by a different lane and an
// index that no part added cannot open one.
func partKey(item string, output, sub int, summary bool) string {
	kind := "c"
	if summary {
		kind = "s"
	}
	return "rpart:" + item + "\x00" + strconv.Itoa(output) + "\x00" + kind + strconv.Itoa(sub)
}

// responseItem refuses an item that was never added at this output index.
func (p *sseProjector) responseItem(item string, output int) error {
	if desc, ok := p.facts["response.item:"+item]; !ok || !strings.HasPrefix(desc, strconv.Itoa(output)+":") {
		return ErrResponseRefused
	}
	return nil
}

// responsesPlan reads an OpenAI Responses event. An item is added once at
// one output index before its parts and deltas, and nothing of it follows
// its done event; a terminal event ends the stream. A call's arguments are
// done once for an item of their kind, and each copy binds its identity fact.
func (p *sseProjector) responsesPlan(doc jsonDoc, typ string) (recordPlan, error) {
	var plan recordPlan
	item, hasItem := doc.get("item_id").text()
	output, hasOutput := doc.get("output_index").index()
	// Arguments that ended unfinished wait for the stream to say it was cut
	// off; only the done events of what was open may come first.
	if len(p.unfinished) > 0 && typ != "response.incomplete" && !strings.HasSuffix(typ, ".done") {
		return plan, ErrResponseRefused
	}
	switch typ {
	case "response.completed", "response.failed", "response.incomplete", "response.cancelled":
		return recordPlan{closes: closeAll, terminal: true, truncated: typ == "response.incomplete"}, nil
	case "response.output_item.added":
		id, ok := doc.get("item", "id").text()
		kind, _ := doc.get("item", "type").text()
		if !ok || !hasOutput {
			return plan, ErrResponseRefused
		}
		if err := p.start("response.item:"+id, strconv.Itoa(output)+":"+kind); err != nil {
			return plan, err
		}
		if err := p.start("response.output:"+strconv.Itoa(output), id); err != nil {
			return plan, err
		}
		return p.responsesAdded(doc, typ, id, output)
	case "response.output_item.done":
		id, ok := doc.get("item", "id").text()
		if kind, _ := doc.get("item", "type").text(); !ok || !hasOutput || p.facts["response.item:"+id] != strconv.Itoa(output)+":"+kind || p.known("ended:response:"+id) {
			return plan, ErrResponseRefused
		}
		plan = endGroups("response:" + id)
		if kind, _ := doc.get("item", "type").text(); kind == "function_call" || kind == "mcp_call" {
			plan.arguments, plan.bind = completeArguments(doc.get("item", "arguments")), "arguments:response:"+id
		}
		return plan, nil
	case "response.content_part.added", "response.reasoning_summary_part.added":
		if !hasItem || !hasOutput || p.responseItem(item, output) != nil {
			return plan, ErrResponseRefused
		}
		return p.responsesAdded(doc, typ, item, output)
	}
	if hasItem && (!hasOutput || p.responseItem(item, output) != nil || p.known("ended:response:"+item)) {
		return plan, ErrResponseRefused
	}
	if base, ok := strings.CutSuffix(typ, ".done"); ok {
		deltas := []string{base + ".delta"}
		switch base {
		case "response.content_part":
			deltas = []string{"response.output_text.delta", "response.refusal.delta"}
		case "response.reasoning_summary_part":
			deltas = []string{"response.reasoning_summary_text.delta"}
		}
		var keys []string
		for _, delta := range deltas {
			if name, known := responseLanes[delta]; known {
				sub, _ := doc.get(name).index()
				keys = append(keys, responseLane(delta, item, output, sub).key)
			}
		}
		plan.closes = func(l *lane) bool { return slices.Contains(keys, l.key) }
		if nestedArgumentDelta[base+".delta"] {
			kind := strconv.Itoa(output) + ":" + strings.TrimSuffix(strings.TrimPrefix(base, "response."), "_arguments")
			if !hasItem || p.facts["response.item:"+item] != kind || p.start("response.arguments.done:"+item, "") != nil {
				return plan, ErrResponseRefused
			}
			plan.arguments, plan.bind = completeArguments(doc.get("arguments")), "arguments:response:"+item
		}
		// Ending a content or reasoning-summary part records the part's end, so
		// no later delta at that same index can open another lane.
		if base == "response.content_part" || base == "response.reasoning_summary_part" {
			summary := base == "response.reasoning_summary_part"
			field := "content_index"
			if summary {
				field = "summary_index"
			}
			sub, hasSub := doc.get(field).index()
			if !hasItem || !hasSub {
				return plan, ErrResponseRefused
			}
			key := partKey(item, output, sub, summary)
			if _, open := p.facts[key]; !open || p.known("ended:"+key) {
				return plan, ErrResponseRefused
			}
			if err := p.declare("ended:"+key, ""); err != nil {
				return plan, err
			}
		}
		return plan, nil
	}
	name, known := responseLanes[typ]
	if !known {
		if strings.HasSuffix(typ, ".delta") {
			return plan, ErrResponseRefused
		}
		return plan, nil
	}
	sub, hasSub := doc.get(name).index()
	if !hasItem || (name != "" && !hasSub) {
		return plan, ErrResponseRefused
	}
	// A content or summary delta must continue a part that was added with this
	// kind and has not ended; an unknown or ended part index refuses.
	if name != "" {
		key := partKey(item, output, sub, name == "summary_index")
		if p.facts[key] != typ || p.known("ended:"+key) {
			return plan, ErrResponseRefused
		}
	}
	part := responseLane(typ, item, output, sub)
	for i := range doc {
		v, path := &doc[i], doc.path(i)
		switch {
		case v.kind != '"', pathIs(path, "type"), pathIs(path, "item_id"), pathIs(path, "obfuscation"):
		case pathIs(path, "delta"):
			part.value = v
			plan.parts = append(plan.parts, part)
		default:
			return plan, ErrResponseRefused
		}
	}
	return plan, nil
}

// responsesAdded opens the lanes of the initial text an added item or part
// carries, which its deltas continue.
func (p *sseProjector) responsesAdded(doc jsonDoc, typ, item string, output int) (recordPlan, error) {
	var plan recordPlan
	content, hasContent := doc.get("content_index").index()
	summary, hasSummary := doc.get("summary_index").index()
	itemType, _ := doc.get("item", "type").text()
	for i := range doc {
		v, path := &doc[i], doc.path(i)
		if v.kind != '"' {
			continue
		}
		delta, sub, ok := "", 0, true
		switch {
		case typ == "response.content_part.added" && pathIs(path, "part", "text"):
			delta, sub, ok = "response.output_text.delta", content, hasContent
		case typ == "response.content_part.added" && pathIs(path, "part", "refusal"):
			delta, sub, ok = "response.refusal.delta", content, hasContent
		case typ == "response.reasoning_summary_part.added" && pathIs(path, "part", "text"):
			delta, sub, ok = "response.reasoning_summary_text.delta", summary, hasSummary
		case typ == "response.output_item.added" && pathIs(path, "item", "arguments"):
			delta = "response.function_call_arguments.delta"
			if itemType == "mcp_call" {
				delta = "response.mcp_call_arguments.delta"
			}
		case typ == "response.output_item.added" && pathIs(path, "item", "input"):
			delta = "response.custom_tool_call_input.delta"
		case typ == "response.output_item.added" && pathIs(path, "item", "code"):
			delta = "response.code_interpreter_call_code.delta"
		case typ == "response.output_item.added" && pathIs(path, "item", "content", -1, "text"):
			delta, sub = "response.output_text.delta", path[2].(int)
		case typ == "response.output_item.added" && pathIs(path, "item", "summary", -1, "text"):
			delta, sub = "response.reasoning_summary_text.delta", path[2].(int)
		}
		if delta == "" {
			continue
		}
		if !ok {
			return plan, ErrResponseRefused
		}
		part := responseLane(delta, item, output, sub)
		part.value = v
		plan.parts = append(plan.parts, part)
		// A content or summary part records its kind and start, so a duplicate
		// part refuses and a later delta must name this same kind.
		if field := responseLanes[delta]; field != "" {
			if err := p.start(partKey(item, output, sub, field == "summary_index"), delta); err != nil {
				return plan, err
			}
		}
	}
	// A part.added that opened no known part is an unknown part under a known
	// item; it is refused rather than forwarded unfenced.
	if len(plan.parts) == 0 && strings.HasSuffix(typ, "_part.added") {
		return plan, ErrResponseRefused
	}
	return plan, nil
}
