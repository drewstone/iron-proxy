package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// minFragment is the shortest base64 fragment worth matching. A shorter run is
// as likely to be ordinary text as part of an encoded secret.
const minFragment = 8

// scrubPair is one thing to find in a response and what replaces it.
type scrubPair struct {
	needle []byte
	repl   []byte
}

// scrubPairsFor lists what a response must not carry for one secret: the real
// value, and the base64 text it takes inside a larger encoded string, which is
// how an echoed HTTP Basic credential arrives.
func scrubPairsFor(realValue, placeholder string) []scrubPair {
	if realValue == "" {
		return nil
	}
	pairs := []scrubPair{{needle: []byte(realValue), repl: []byte(placeholder)}}
	for _, encode := range []func(string) string{url.QueryEscape, url.PathEscape, html.EscapeString} {
		pairs = append(pairs, scrubPair{needle: []byte(encode(realValue)), repl: []byte(encode(placeholder))})
	}
	for _, escapeHTML := range []bool{true, false} {
		content := func(value string) []byte {
			var out bytes.Buffer
			encoder := json.NewEncoder(&out)
			encoder.SetEscapeHTML(escapeHTML)
			_ = encoder.Encode(value)
			return out.Bytes()[1 : out.Len()-2]
		}
		pairs = append(pairs, scrubPair{needle: content(realValue), repl: content(placeholder)})
	}
	for pad := 0; pad < 3; pad++ {
		needle := base64Fragment(realValue, pad)
		repl := base64Fragment(placeholder, pad)
		if len(needle) >= minFragment && repl != "" {
			pairs = append(pairs, scrubPair{needle: []byte(needle), repl: []byte(repl)})
		}
	}
	return pairs
}

// base64Fragment returns the base64 text that depends on value alone when pad
// bytes of other data come before it in the stream. Base64 turns three bytes
// into four characters, so the same value encodes three ways depending on
// where it starts; the characters that also carry a neighbour's bits are left
// out.
func base64Fragment(value string, pad int) string {
	encoded := base64.RawStdEncoding.EncodeToString(append(make([]byte, pad), value...))
	start := (8*pad + 5) / 6
	end := 8 * (pad + len(value)) / 6
	if end <= start {
		return ""
	}
	return encoded[start:end]
}

// scrubber replaces every needle with its replacement.
type scrubber struct {
	pairs     []scrubPair
	maxNeedle int
}

func newScrubber(pairs []scrubPair) *scrubber {
	s := &scrubber{pairs: pairs}
	for _, p := range pairs {
		s.maxNeedle = max(s.maxNeedle, len(p.needle))
	}
	return s
}

// scan returns data with every needle replaced. Unless final, the trailing
// held bytes of data may be the start of a needle that the next bytes finish:
// they are not in out, and the caller carries them into the next scan.
func (s *scrubber) scan(data []byte, final bool) (out []byte, held int) {
	i := 0
	for {
		at, which := -1, 0
		for p := range s.pairs {
			idx := bytes.Index(data[i:], s.pairs[p].needle)
			if idx < 0 {
				continue
			}
			if at < 0 || idx < at || (idx == at && len(s.pairs[p].needle) > len(s.pairs[which].needle)) {
				at, which = idx, p
			}
		}
		if at < 0 {
			break
		}
		out = append(out, data[i:i+at]...)
		out = append(out, s.pairs[which].repl...)
		i += at + len(s.pairs[which].needle)
	}
	rest := data[i:]
	if !final {
		held = s.partial(rest)
	}
	return append(out, rest[:len(rest)-held]...), held
}

// partial is the length of the longest tail of rest that is the start of a
// needle.
func (s *scrubber) partial(rest []byte) int {
	for k := min(len(rest), s.maxNeedle-1); k > 0; k-- {
		tail := rest[len(rest)-k:]
		for _, p := range s.pairs {
			if len(p.needle) > k && bytes.HasPrefix(p.needle, tail) {
				return k
			}
		}
	}
	return 0
}

func (s *scrubber) text(value string) string {
	out, _ := s.scan([]byte(value), true)
	return string(out)
}

// scrubReader scrubs a body as it streams. It delivers what it has as soon as
// it can prove no needle starts in it, so a stream that pauses is not held
// longer than the few bytes that begin a needle.
type scrubReader struct {
	src     io.Reader
	closer  io.Closer
	scrub   *scrubber
	chunk   []byte
	pending []byte
	ready   []byte
	done    bool
	err     error
}

func newScrubReader(src io.Reader, closer io.Closer, s *scrubber) *scrubReader {
	return &scrubReader{src: src, closer: closer, scrub: s, chunk: make([]byte, 32<<10)}
}

func (r *scrubReader) Read(p []byte) (int, error) {
	for len(r.ready) == 0 {
		if r.done {
			return 0, r.err
		}
		n, err := r.src.Read(r.chunk)
		r.pending = append(r.pending, r.chunk[:n]...)
		out, held := r.scrub.scan(r.pending, err != nil)
		r.ready = out
		r.pending = append(r.pending[:0], r.pending[len(r.pending)-held:]...)
		if err != nil {
			r.done, r.err = true, err
		}
	}
	n := copy(p, r.ready)
	r.ready = r.ready[n:]
	return n, nil
}

func (r *scrubReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// TransformResponse removes the real value from a response to a request that
// carried a secret with scrub_response set. A host that echoes its request
// headers, quotes the credential in an error, or redirects with it would
// otherwise give the value to the caller. Headers are scrubbed whole; a body
// is scrubbed as it streams, so its length changes and the response is sent
// chunked.
func (s *Secrets) TransformResponse(ctx context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	if state == nil {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	resp.Request = req
	pairs, names := state.pairs, state.names

	if len(pairs) == 0 {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	tctx.Annotate("secret_response_scrubbed", names)
	scrub := newScrubber(pairs)

	scrubHeaders(resp.Header, scrub)

	if req.Method == http.MethodHead || resp.ContentLength == 0 ||
		resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	// Bytes the proxy cannot read as text cannot be scrubbed. The request had
	// its Accept-Encoding removed, so net/http decodes gzip itself; any other
	// encoding is a host that compresses unasked.
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		tctx.Annotate("rejected", names)
		tctx.Annotate("reject_reason", "response_encoding")
		message := []byte("response encoding cannot be checked for a held secret\n")
		return &transform.TransformResult{
			Action: transform.ActionReject,
			Response: &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": {"text/plain"}},
				Body:          transform.NewBufferedBodyFromBytes(message),
				ContentLength: int64(len(message)),
				Request:       req,
			},
		}, nil
	}

	// Read the upstream stream directly: the buffered body would hold the
	// whole response in memory first.
	body := transform.RequireBufferedBody(resp.Body)
	stream := body.StreamingReader()
	closer, _ := stream.(io.Closer)
	if closer == nil {
		closer = body
	}
	resp.Body = transform.NewBufferedBody(newScrubReader(stream, closer, scrub), 0)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func scrubHeaders(header http.Header, scrub *scrubber) {
	masked := make(http.Header, len(header))
	for name, values := range header {
		for _, value := range values {
			key := scrub.text(name)
			masked[key] = append(masked[key], scrub.text(value))
		}
	}
	clear(header)
	for name, values := range masked {
		header[name] = values
	}
}

// MaskResponseText uses only this request's selected source values, including after rotation.
func MaskResponseText(req *http.Request, value string) string {
	if req == nil {
		return value
	}
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	if state == nil {
		return value
	}
	return newScrubber(state.pairs).text(value)
}

// MaskResponseReader preserves streaming and WebSocket message boundaries with bounded memory.
func MaskResponseReader(req *http.Request, src io.Reader) io.Reader {
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	if state == nil {
		return src
	}
	return newScrubReader(src, nil, newScrubber(state.pairs))
}
