package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The strict JSON policy of protected payloads, shared by server-sent event
// records, their tool-call arguments and JSON documents. encoding/json owns
// the grammar; this policy adds what a lenient reader would repair or choose
// between, and the bounds of what a payload may make the proxy hold
// (semantic.go owns the limits).

// jsonValue is one value of a parsed record. Its path is a link to the value
// that contains it, so a record holds one entry per value at any depth.
type jsonValue struct {
	parent     int    // index of the containing value; -1 at the top
	key        string // member name (after projection) in an object
	pos        int    // position in an array; -1 in an object
	kind       byte   // '"' string, '0' number, 'l' literal, '{' or '['
	str        string
	start, end int
}

type jsonDoc []jsonValue

type jsonFrame struct {
	object, expectKey bool
	key               string
	next              int
	value             int
	keys              map[string]bool
	keyBytes          int
}

// jsonPolicy admits exactly one JSON value token by token: valid UTF-8,
// paired surrogate escapes, object keys unique after the request's
// projection (so a reflected key cannot collide with another), and depth and
// retained key bytes within the protected bounds, checked before they grow.
type jsonPolicy struct {
	scrub    *scrubber
	stack    []jsonFrame
	keyBytes int
	started  bool
	done     bool
}

// admit takes the next token, spelled raw, and returns the value it is or
// opens; ok is false for keys and closing delimiters. index is the position
// the caller gives that value, linked from its children.
func (j *jsonPolicy) admit(tok json.Token, raw []byte, index int) (jsonValue, bool, error) {
	if j.done {
		return jsonValue{}, false, ErrResponseRefused
	}
	j.started = true
	if _, isString := tok.(string); isString && !validJSONString(raw) {
		return jsonValue{}, false, ErrResponseRefused
	}
	if delim, ok := tok.(json.Delim); ok && (delim == '}' || delim == ']') {
		j.keyBytes -= j.stack[len(j.stack)-1].keyBytes
		j.stack = j.stack[:len(j.stack)-1]
		j.done = len(j.stack) == 0
		return jsonValue{}, false, nil
	}
	v := jsonValue{parent: -1, pos: -1, kind: 'l'}
	if n := len(j.stack); n > 0 {
		top := &j.stack[n-1]
		if top.expectKey {
			key, _ := tok.(string) // The decoder reads only a string as a key.
			if j.scrub != nil {
				key = j.scrub.text(key)
			}
			if top.keys[key] || j.keyBytes+len(key) > maxProtectedRecord {
				return jsonValue{}, false, ErrResponseRefused
			}
			j.keyBytes += len(key)
			top.keyBytes += len(key)
			top.keys[key], top.key, top.expectKey = true, key, false
			return jsonValue{}, false, nil
		}
		v.parent = top.value
		if top.object {
			v.key, top.expectKey = top.key, true
		} else {
			v.pos = top.next
			top.next++
		}
	}
	switch t := tok.(type) {
	case json.Delim:
		if len(j.stack) >= maxProtectedDepth {
			return jsonValue{}, false, ErrResponseRefused
		}
		v.kind = byte(t)
		frame := jsonFrame{object: t == '{', expectKey: t == '{', value: index}
		if frame.object {
			frame.keys = map[string]bool{}
		}
		j.stack = append(j.stack, frame)
	case string:
		v.kind, v.str = '"', t
	case json.Number:
		v.kind, v.str = '0', string(t)
	}
	j.done = len(j.stack) == 0
	return v, true, nil
}

// tokenStart skips the separators the decoder consumed before a token.
func tokenStart(raw []byte, start, end int) int {
	for start < end && strings.IndexByte(" \t\r\n,:", raw[start]) >= 0 {
		start++
	}
	return start
}

// parseJSON reads one complete record under the strict policy, refusing it
// once it holds more values than a record may. When each is set, it is given
// every admitted string token, key or value, with its span in raw.
func parseJSON(raw []byte, scrub *scrubber, each func(s string, start, end int)) (jsonDoc, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	policy := jsonPolicy{scrub: scrub}
	var doc jsonDoc
	offset := 0
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrResponseRefused
		}
		end := int(decoder.InputOffset())
		start := tokenStart(raw, offset, end)
		offset = end
		v, isValue, err := policy.admit(tok, raw[start:end], len(doc))
		if err != nil {
			return nil, err
		}
		if s, isString := tok.(string); isString && each != nil {
			each(s, start, end)
		}
		if !isValue {
			continue
		}
		if len(doc) >= maxProtectedValues {
			return nil, ErrResponseRefused
		}
		v.start, v.end = start, end
		doc = append(doc, v)
	}
	if !policy.done {
		return nil, ErrResponseRefused
	}
	return doc, nil
}

// jsonDocReader passes a protected JSON document on as the strict policy
// admits it. A byte leaves only once the decoder has read the token it ends,
// so a document that turns malformed, ambiguous or unfinished is refused
// before its bad part, and what it holds is bounded by one token.
type jsonDocReader struct {
	src     io.Reader
	decoder *json.Decoder
	policy  jsonPolicy
	raw     []byte // bytes read from src and not yet passed on
	base    int64  // stream offset of raw[0]
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func newJSONDocReader(src io.Reader, scrub *scrubber) *jsonDocReader {
	r := &jsonDocReader{src: src, policy: jsonPolicy{scrub: scrub}}
	r.decoder = json.NewDecoder(readerFunc(r.fill))
	r.decoder.UseNumber()
	return r
}

// fill reads for the decoder and keeps what it read until it is admitted.
func (r *jsonDocReader) fill(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.raw = append(r.raw, p[:n]...)
	if len(r.raw) > maxProtectedRecord {
		return n, ErrResponseRefused
	}
	return n, err
}

func (r *jsonDocReader) Read(p []byte) (int, error) {
	for {
		if admitted := int(r.decoder.InputOffset() - r.base); admitted > 0 {
			n := copy(p, r.raw[:admitted])
			r.raw = append(r.raw[:0], r.raw[n:]...)
			r.base += int64(n)
			// The whole document is bounded, not only each token, so a matched
			// MCP server's io.ReadAll of a protected JSON body it composes with
			// cannot be made to retain an unbounded aggregate.
			if r.base > maxProtectedRecord {
				return 0, ErrResponseRefused
			}
			return n, nil
		}
		tok, err := r.decoder.Token()
		if err == io.EOF && (r.policy.done || !r.policy.started) {
			// Whitespace after the value, and an empty body, end it cleanly.
			return 0, io.EOF
		}
		if err != nil {
			return 0, ErrResponseRefused
		}
		end := int(r.decoder.InputOffset() - r.base)
		if _, _, err := r.policy.admit(tok, r.raw[tokenStart(r.raw, 0, end):end], 0); err != nil {
			return 0, err
		}
	}
}

// validJSONString reports that a raw string token is UTF-8 and pairs every
// surrogate escape. The decoder has already checked its escapes.
func validJSONString(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		unit, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 32)
		i += 4
		switch {
		case unit >= 0xDC00 && unit < 0xE000:
			return false
		case unit >= 0xD800 && unit < 0xDC00:
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 32)
			if low < 0xDC00 || low >= 0xE000 {
				return false
			}
			i += 6
		}
	}
	return true
}

// path returns the keys (string) and indexes (int) from the top to value i;
// it is built on demand, never kept.
func (d jsonDoc) path(i int) []any {
	var path []any
	for ; d[i].parent >= 0; i = d[i].parent {
		if d[i].pos >= 0 {
			path = append(path, d[i].pos)
		} else {
			path = append(path, d[i].key)
		}
	}
	slices.Reverse(path)
	return path
}

// get finds the value at path by walking children from the top.
func (d jsonDoc) get(path ...any) *jsonValue {
	at := 0
	for _, step := range path {
		next := -1
		for i := at + 1; i < len(d) && next < 0; i++ {
			if d[i].parent != at {
				continue
			}
			switch s := step.(type) {
			case string:
				if d[i].pos < 0 && d[i].key == s {
					next = i
				}
			case int:
				if d[i].pos == s {
					next = i
				}
			}
		}
		if next < 0 {
			return nil
		}
		at = next
	}
	return &d[at]
}

// pathIs reports a path equal to pattern, where an index of -1 matches any.
func pathIs(path []any, pattern ...any) bool {
	return len(path) == len(pattern) && pathIn(path, pattern...)
}

// pathIn reports a path that begins with pattern.
func pathIn(path []any, pattern ...any) bool {
	if len(path) < len(pattern) {
		return false
	}
	for i, want := range pattern {
		switch w := want.(type) {
		case int:
			if got, ok := path[i].(int); !ok || (w >= 0 && got != w) {
				return false
			}
		case string:
			if got, ok := path[i].(string); !ok || got != w {
				return false
			}
		}
	}
	return true
}

// index reads a non-negative integer.
func (v *jsonValue) index() (int, bool) {
	if v == nil || v.kind != '0' {
		return 0, false
	}
	n, err := strconv.Atoi(v.str)
	return n, err == nil && n >= 0
}

// text reads a string short enough to keep as a lane identity.
func (v *jsonValue) text() (string, bool) {
	if v == nil || v.kind != '"' || len(v.str) > maxLaneMeta {
		return "", false
	}
	return v.str, true
}

func appendJSONString(dst []byte, s string) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(s) // Encoding a string cannot fail.
	return append(dst, bytes.TrimSuffix(b.Bytes(), []byte("\n"))...)
}

func quote(s string) string { return string(appendJSONString(nil, s)) }

// validProjection reports that scrubbed bytes are still one well-formed JSON
// value under the strict policy. A projection that turned a numeric token into
// a word placeholder, or otherwise broke the grammar, is refused rather than
// completed. The scrub has already run, so no value is projected again here.
func validProjection(scrubbed []byte) bool {
	_, err := parseJSON(scrubbed, nil, nil)
	return err == nil
}

// finish scrubs a whole record, which covers every value it holds complete,
// then refuses a record the scrub left invalid JSON (for example a numeric
// token projected to a word placeholder), so a completed record is always
// valid. Keys were checked unique after projection when the record was parsed.
func (p *sseProjector) finish(record []byte, original string) (string, error) {
	scrubbed, _ := p.scrub.scan(nil, record, true)
	if !validProjection(scrubbed) {
		return "", ErrResponseRefused
	}
	if string(scrubbed) == original {
		return original, nil
	}
	return string(scrubbed), nil
}

// projectLane projects the text a lane carries. A tool call's arguments are
// one JSON value, so their lane holds the text whole, within one record's bound
// across every open argument lane, and projects it once the lane ends: no part
// of an argument is sent before all of it is admitted. Every other lane is the
// flat scrub.
func (p *sseProjector) projectLane(l *lane, text []byte, final bool) ([]byte, int, error) {
	if !l.nested {
		out, held := p.scrub.scan(nil, text, final)
		return out, held, nil
	}
	p.argBytes += len(text) - len(l.held)
	if !final {
		if p.argBytes > maxProtectedRecord {
			return nil, 0, ErrResponseRefused
		}
		return nil, len(text), nil
	}
	p.argBytes -= len(text)
	out, identity, err := projectArguments(p.scrub, text)
	if err == nil && l.bind != "" {
		err = p.declare(l.bind, identity)
	}
	return out, 0, err
}

// projectArguments projects a tool call's complete arguments, JSON carried as
// the text of a lane or of a done event. They are read under the strict policy
// of a record, so malformed or unfinished JSON, a bad escape, an unpaired
// surrogate and a key the projection would make equal to another are refused.
// Each string, key or value, is decoded, projected and re-encoded only when the
// scrub changed it; the whole text is then scrubbed, for a value outside a
// string, and must still be one valid JSON value. Empty arguments stay empty.
// identity is the digest of the projected value as decoded, so two spellings
// of one value, escaped differently, have the same identity.
func projectArguments(scrub *scrubber, text []byte) (out []byte, identity string, err error) {
	if len(text) == 0 {
		return nil, argumentIdentity(nil, nil), nil
	}
	last := 0
	_, err = parseJSON(text, scrub, func(s string, start, end int) {
		if projected := scrub.text(s); projected != s {
			out = appendJSONString(append(out, text[last:start]...), projected)
			last = end
		}
	})
	if err != nil {
		return nil, "", err
	}
	out, _ = scrub.scan(nil, append(out, text[last:]...), true)
	doc, err := parseJSON(out, nil, nil)
	if err != nil {
		return nil, "", ErrResponseRefused
	}
	return out, argumentIdentity(out, doc), nil
}

// argumentIdentity is a fixed-size digest of a parsed value: each value's
// place, kind and decoded string, or its raw spelling for a number, literal
// or delimiter. Strings are length-prefixed, so no two values share one.
func argumentIdentity(raw []byte, doc jsonDoc) string {
	sum := sha256.New()
	for _, v := range doc {
		s := v.str
		if v.kind != '"' {
			s = string(raw[v.start:v.end])
		}
		fmt.Fprintf(sum, "%d %d %c %d:%s %d:%s\n", v.parent, v.pos, v.kind, len(v.key), v.key, len(s), s)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// completeArguments is the arguments string a done event repeats, if any.
func completeArguments(v *jsonValue) []*jsonValue {
	if v == nil || v.kind != '"' {
		return nil
	}
	return []*jsonValue{v}
}
