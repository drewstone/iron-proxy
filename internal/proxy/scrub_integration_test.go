package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// The held value is shaped like a cloud secret key: letters, digits and the
// punctuation that escapers treat differently (+ / = & _).
const (
	reflectReal        = "hf_REAL+01/23&456789abcdef=XYZ_0123456789abcdef"
	reflectPlaceholder = "proxy-declared-0-token.SALT"
	// nameReal is a second held value that is a valid field name and starts
	// with a letter, so Go's canonical form of it differs from it.
	nameReal        = "kq7d9m2x4v8b1n6c3z5w0p8r7t2y4u6i"
	namePlaceholder = "name-placeholder-0001"
)

// reflection is one way a host can hand the injected value back. form spells
// a value in that encoding. placeholder, when set, is what the scrubbed
// response carries instead of form(placeholder); stable, when set, is the
// part of form(value) that depends on the value alone.
type reflection struct {
	name        string
	form        func(string) string
	placeholder func(string) string
	stable      func(string) string
}

func everyByte(value string, spell func(byte) string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		b.WriteString(spell(value[i]))
	}
	return b.String()
}

func everyRune(value string, spell func(rune) string) string {
	var b strings.Builder
	for _, r := range value {
		b.WriteString(spell(r))
	}
	return b.String()
}

func jsonString(escapeHTML bool) func(string) string {
	return func(value string) string {
		var out strings.Builder
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(escapeHTML)
		_ = encoder.Encode(value)
		return strings.TrimSuffix(out.String(), "\n")
	}
}

// formatChars are the Unicode format characters (category Cf) a host may
// interleave with the value.
var formatChars = []rune{0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD}

func interleave(gap func(rune) string, per int) func(string) string {
	return func(value string) string {
		var b strings.Builder
		next := 0
		for i, r := range []rune(value) {
			if i > 0 {
				for range per {
					b.WriteString(gap(formatChars[next%len(formatChars)]))
					next++
				}
			}
			b.WriteRune(r)
		}
		return b.String()
	}
}

func reversed(value string) string {
	runes := []rune(value)
	slices.Reverse(runes)
	return string(runes)
}

func rot13(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, value)
}

// middle is the part of a base64 text that depends on value alone when
// prefix comes before it: the characters that also carry a neighbour's bits
// change with the neighbour, so only the middle is a stable spelling.
func middle(encode func([]byte) string, bits int, prefix string) func(string) string {
	return func(value string) string {
		encoded := encode([]byte(prefix + value))
		return encoded[(8*len(prefix)+bits-1)/bits : 8*(len(prefix)+len(value))/bits]
	}
}

func reflections() []reflection {
	pct := func(format string) func(string) string {
		return func(v string) string {
			return everyByte(v, func(b byte) string { return fmt.Sprintf(format, b) })
		}
	}
	jsonU := func(format string) func(string) string {
		return func(v string) string {
			return everyRune(v, func(r rune) string { return fmt.Sprintf(format, r) })
		}
	}
	rows := []reflection{
		{name: "verbatim", form: func(v string) string { return v }},
		{name: "query escape", form: url.QueryEscape},
		{name: "path escape", form: url.PathEscape},
		{name: "query escape lowercase hex", form: func(v string) string {
			return everyByte(v, func(b byte) string {
				if url.QueryEscape(string(b)) == string(b) {
					return string(b)
				}
				return fmt.Sprintf("%%%02x", b)
			})
		}},
		{name: "percent every byte upper", form: pct("%%%02X")},
		{name: "percent every byte lower", form: pct("%%%02x")},
		{name: "html escape", form: html.EscapeString},
		{name: "html decimal references", form: func(v string) string {
			return everyRune(v, func(r rune) string { return "&#" + strconv.Itoa(int(r)) + ";" })
		}},
		{name: "html hex references", form: func(v string) string { return everyRune(v, func(r rune) string { return fmt.Sprintf("&#x%x;", r) }) }},
		{name: "json escaping html", form: jsonString(true)},
		{name: "json", form: jsonString(false)},
		{name: "json u escapes lower", form: jsonU(`\u%04x`)},
		{name: "json u escapes upper", form: jsonU(`\u%04X`)},
		{name: "backslash x escapes", form: func(v string) string { return everyByte(v, func(b byte) string { return fmt.Sprintf(`\x%02x`, b) }) }},
		{name: "hex lower", form: func(v string) string { return hex.EncodeToString([]byte(v)) }},
		{name: "hex upper", form: func(v string) string { return strings.ToUpper(hex.EncodeToString([]byte(v))) }},
		{name: "reversed", form: reversed},
		{name: "rot13", form: rot13},
		{name: "format characters between letters", form: interleave(func(r rune) string { return string(r) }, 1), placeholder: func(v string) string { return v }},
		{name: "format character runs between letters", form: interleave(func(r rune) string { return string(r) }, 4), placeholder: func(v string) string { return v }},
		{name: "json escaped format characters", form: interleave(func(r rune) string { return fmt.Sprintf(`\u%04x`, r) }, 1), placeholder: func(v string) string { return v }},
		{name: "query escape twice", form: func(v string) string { return url.QueryEscape(url.QueryEscape(v)) }},
		{name: "path escape twice", form: func(v string) string { return url.PathEscape(url.PathEscape(v)) }},
		{name: "html template inside json", form: func(v string) string { return jsonString(true)(htmlTemplate(v)) }},
		{name: "json inside json", form: func(v string) string { return jsonString(true)(jsonString(true)(v)) }},
	}
	for _, enc := range []struct {
		name     string
		encoding *base64.Encoding
	}{
		{"base64", base64.StdEncoding}, {"base64 unpadded", base64.RawStdEncoding},
		{"base64url", base64.URLEncoding}, {"base64url unpadded", base64.RawURLEncoding},
	} {
		// Prefix lengths 0, 1 and 2 cover the three base64 alignments.
		for _, prefix := range []string{"", "u", "u:"} {
			rows = append(rows, reflection{
				name: fmt.Sprintf("%s after %q", enc.name, prefix),
				form: func(v string) string { return enc.encoding.EncodeToString([]byte(prefix + v)) },
				// The scrub can only replace the characters that depend on the
				// value alone, so that middle is what is asserted.
				placeholder: middle(enc.encoding.EncodeToString, 6, prefix),
				stable:      middle(enc.encoding.EncodeToString, 6, prefix),
			})
		}
	}
	for _, enc := range []struct {
		name   string
		encode func([]byte) string
	}{
		{"base32", base32.StdEncoding.EncodeToString},
		{"base32 lowercase", func(b []byte) string { return strings.ToLower(base32.StdEncoding.EncodeToString(b)) }},
		{"base32hex", base32.HexEncoding.EncodeToString},
		{"base32hex lowercase unpadded", func(b []byte) string {
			return strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		}},
	} {
		for _, prefix := range []string{"", "u", "u:", "us:", "user"} {
			rows = append(rows, reflection{
				name:        fmt.Sprintf("%s after %q", enc.name, prefix),
				form:        func(v string) string { return enc.encode([]byte(prefix + v)) },
				placeholder: middle(enc.encode, 5, prefix),
				stable:      middle(enc.encode, 5, prefix),
			})
		}
	}
	return rows
}

// htmlTemplate escapes value as html/template writes it into HTML text.
func htmlTemplate(value string) string {
	var b strings.Builder
	_ = template.Must(template.New("").Parse("{{.}}")).Execute(&b, value)
	return b.String()
}

// wrapped is base64 of prefix+value cut into lines as MIME (76, CRLF), PEM
// (64, LF) and Ruby (60, LF) write it, and indented as in a YAML block.
func wrapped(value string) []string {
	var out []string
	for _, prefix := range []string{"", "u", "u:"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(prefix + value))
		for _, wrap := range []struct {
			width int
			eol   string
		}{{76, "\r\n"}, {64, "\n"}, {60, "\n"}, {64, "\n    "}} {
			var b strings.Builder
			for at := 0; at < len(encoded); at += wrap.width {
				b.WriteString(encoded[at:min(at+wrap.width, len(encoded))] + wrap.eol)
			}
			out = append(out, b.String())
		}
	}
	return out
}

// unwrapped removes the line breaks a wrapped or JSON-escaped body carries.
func unwrapped(text string) string {
	return strings.NewReplacer("\r", "", "\n", "", `\r`, "", `\n`, "", " ", "").Replace(text)
}

func gzipped(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// placeholderOf is what the scrubbed response carries for one reflection.
func (r reflection) placeholderOf() string {
	if r.placeholder != nil {
		return r.placeholder(reflectPlaceholder)
	}
	return r.form(reflectPlaceholder)
}

// realOf is the spelling of the real value that must not survive. For base64
// it is the middle, which holds every bit of the value but its edges.
func (r reflection) realOf() string {
	if r.stable != nil {
		return r.stable(reflectReal)
	}
	return r.form(reflectReal)
}

// reflectingUpstream is a declared host that returns the credential it was
// sent in every covered encoding: in the body, in headers, in trailers, split
// across a flush, and over a WebSocket.
func reflectingUpstream(t *testing.T, plain []byte, release <-chan struct{}) *httptest.Server {
	t.Helper()
	rows := reflections()
	lines := func(token string) string {
		var b strings.Builder
		for i, row := range rows {
			fmt.Fprintf(&b, "%d %s\n", i, row.form(token))
		}
		return b.String()
	}
	token := func(r *http.Request) string {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got != reflectReal {
			t.Errorf("upstream got %q, want the injected value", got)
		}
		return got
	}
	nameToken := func(r *http.Request) string {
		if got := r.Header.Get("X-Api-Key"); got != nameReal {
			t.Errorf("upstream got %q, want the injected name value", got)
		}
		return nameReal
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wrapped":
			value := token(r)
			for _, form := range wrapped(value) {
				_, _ = io.WriteString(w, form+"\n")
				_, _ = io.WriteString(w, jsonString(false)(form)+"\n")
			}
		case "/header-name":
			// Set directly so the fixture does not canonicalize the name.
			w.Header()[nameToken(r)] = []string{"1"}
			_, _ = io.WriteString(w, "ok")
		case "/header-name-reversed", "/header-name-rot13":
			name := reversed(nameToken(r))
			if r.URL.Path == "/header-name-rot13" {
				name = rot13(nameReal)
			}
			w.Header()[name] = []string{"1"}
			_, _ = io.WriteString(w, "ok")
		case "/trailer-name":
			w.Header()["Trailer"] = []string{nameToken(r)}
			_, _ = io.WriteString(w, "ok")
			w.Header()[nameReal] = []string{"1"}
		case "/trailer-late":
			// An undeclared trailer arrives only after the body.
			nameToken(r)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {}\n\n")
			w.(http.Flusher).Flush()
			w.Header()[http.TrailerPrefix+nameReal] = []string{"1"}
		case "/gzip-once":
			if r.Header.Get("Accept-Encoding") != "gzip" {
				t.Errorf("upstream was asked for %q, want gzip", r.Header.Get("Accept-Encoding"))
			}
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gzipped([]byte("stored=" + token(r))))
		case "/gzip-two-lines":
			w.Header()["Content-Encoding"] = []string{"identity", "gzip"}
			_, _ = w.Write(gzipped([]byte(token(r))))
		case "/gzip-twice":
			w.Header()["Content-Encoding"] = []string{"gzip", "gzip"}
			_, _ = w.Write(gzipped(gzipped([]byte(token(r)))))
		case "/grpc":
			// One compressed gRPC message, as grpc-go answers a request that
			// was itself compressed.
			message := gzipped([]byte(token(r)))
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Encoding", "gzip")
			frame := binary.BigEndian.AppendUint32([]byte{1}, uint32(len(message)))
			_, _ = w.Write(append(frame, message...))
		case "/ws-interleaved":
			// Realtime-shaped deltas of two streams under one key.
			value := token(r)
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			for _, message := range []string{
				`{"type":"response.audio_transcript.delta","delta":"key=` + value[:24] + `"}`,
				`{"type":"response.audio.delta","delta":"UklGRiQAAABXQVZF"}`,
				`{"type":"response.audio_transcript.delta","delta":"` + jsonString(false)(value[24:])[1:len(jsonString(false)(value[24:]))-1] + ` end"}`,
				"after",
			} {
				if conn.Write(r.Context(), websocket.MessageText, []byte(message)) != nil {
					return
				}
			}
			_, _, _ = conn.Read(r.Context())
		case "/ws-split":
			value := token(r)
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			for _, message := range []string{"key=" + value[:24], value[24:] + " end", "after"} {
				if conn.Write(r.Context(), websocket.MessageText, []byte(message)) != nil {
					return
				}
			}
			_, _, _ = conn.Read(r.Context())
		case "/reflect":
			value := token(r)
			var names []string
			for i := range rows {
				if inTrailer(rows[i]) {
					names = append(names, fmt.Sprintf("X-Trailer-%d", i))
				}
			}
			w.Header().Set("Trailer", strings.Join(names, ", "))
			for i, row := range rows {
				w.Header().Set(fmt.Sprintf("X-Echo-%d", i), row.form(value))
			}
			_, _ = io.WriteString(w, lines(value))
			// Each split value is written in two flushes, cut inside it.
			for i, row := range rows {
				spelled := row.form(value)
				cut := len(spelled) / 2
				fmt.Fprintf(w, "split %d ", i)
				_, _ = io.WriteString(w, spelled[:cut])
				w.(http.Flusher).Flush()
				time.Sleep(2 * time.Millisecond)
				_, _ = io.WriteString(w, spelled[cut:]+"\n")
			}
			for i, row := range rows {
				if inTrailer(row) {
					w.Header().Set(fmt.Sprintf("X-Trailer-%d", i), row.form(value))
				}
			}
		case "/events":
			token(r)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"delta\":\"hi\"}\n\n")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "data: done\n\n")
		case "/plain":
			token(r)
			w.Header().Set("X-Plain", "100%25 & \\u0041 &#65; \u200b")
			_, _ = w.Write(plain)
		case "/ws":
			value := token(r)
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			_ = conn.Write(r.Context(), websocket.MessageText, []byte(lines(value)))
			_, _, _ = conn.Read(r.Context())
		}
	}))
}

// inTrailer picks the reflections short enough that together they fit the
// Go client's limit on trailer size; the body and headers carry every one.
func inTrailer(row reflection) bool {
	return len(row.form(reflectReal)) <= 120
}

func scrubbingProxy(t *testing.T, scrub bool) string {
	t.Helper()
	t.Setenv("IRON_SCRUB_TEST_SECRET", reflectReal)
	t.Setenv("IRON_SCRUB_NAME_SECRET", nameReal)
	factory, err := transform.Lookup("secrets")
	require.NoError(t, err)
	secrets, err := factory(mustYAMLNode(t, fmt.Sprintf(`
secrets:
  - source: {type: env, var: IRON_SCRUB_TEST_SECRET}
    rules: [{host: "127.0.0.1"}]
    replace:
      proxy_value: %q
      match_headers: [Authorization]
      scrub_response: %t
  - source: {type: env, var: IRON_SCRUB_NAME_SECRET}
    rules: [{host: "127.0.0.1"}]
    replace:
      proxy_value: %q
      match_headers: [X-Api-Key]
      scrub_response: %t
`, reflectPlaceholder, scrub, namePlaceholder, scrub)), testLogger())
	require.NoError(t, err)
	_, httpAddr, _, _ := startProxyWithTransforms(t, []transform.Transformer{secrets})
	return httpAddr
}

func throughProxy(t *testing.T, httpAddr, upstreamAddr, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+path, nil)
	require.NoError(t, err)
	req.Host = upstreamAddr
	req.Header.Set("Authorization", "Bearer "+reflectPlaceholder)
	req.Header.Set("X-Api-Key", namePlaceholder)
	resp, err := http.DefaultTransport.(*http.Transport).Clone().RoundTrip(req)
	require.NoError(t, err)
	return resp
}

// requireScrubbed checks one surface: no reflection's real spelling is
// anywhere in it, and each numbered reflection carries the placeholder.
func requireScrubbed(t *testing.T, surface string, text string, numbered func(i int) (string, bool)) {
	t.Helper()
	require.NotContains(t, text, reflectReal, surface)
	for i, row := range reflections() {
		require.NotContains(t, text, row.realOf(), "%s: %s leaked", surface, row.name)
		if got, carried := numbered(i); carried {
			require.Contains(t, got, row.placeholderOf(), "%s: %s lost the placeholder", surface, row.name)
		}
	}
}

func TestIntegration_ResponseScrubCoversEveryReflectedEncoding(t *testing.T) {
	plain := make([]byte, 1<<20)
	_, _ = rand.Read(plain[:len(plain)/2])
	// Text full of escapes and format characters that spell nothing held.
	filler := "100%25 & \\u0041 &#65; &amp; %e2%80%8b \u200b\ufeff hf_REAL+01/23& " + reflectReal[:len(reflectReal)-1] + "Q\n"
	for at := len(plain) / 2; at < len(plain); at += copy(plain[at:], filler) {
	}
	release := make(chan struct{})
	upstream := reflectingUpstream(t, plain, release)
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	httpAddr := scrubbingProxy(t, true)

	t.Run("body headers trailers and split chunks", func(t *testing.T) {
		resp := throughProxy(t, httpAddr, upstreamAddr, "/reflect")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		bodyLines := strings.Split(string(body), "\n")
		requireScrubbed(t, "body", string(body), func(i int) (string, bool) { return bodyLines[i], true })
		requireScrubbed(t, "split body", string(body), func(i int) (string, bool) { return bodyLines[len(reflections())+i], true })

		var headers strings.Builder
		require.NoError(t, resp.Header.Write(&headers))
		requireScrubbed(t, "headers", headers.String(), func(i int) (string, bool) { return resp.Header.Get(fmt.Sprintf("X-Echo-%d", i)), true })

		var trailers strings.Builder
		require.NoError(t, resp.Trailer.Write(&trailers))
		requireScrubbed(t, "trailers", trailers.String(), func(i int) (string, bool) {
			return resp.Trailer.Get(fmt.Sprintf("X-Trailer-%d", i)), inTrailer(reflections()[i])
		})
	})

	t.Run("websocket message", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(ctx, "ws://"+httpAddr+"/ws", &websocket.DialOptions{
			Host:       upstreamAddr,
			HTTPHeader: http.Header{"Authorization": {"Bearer " + reflectPlaceholder}},
		})
		require.NoError(t, err)
		defer conn.CloseNow()
		_, message, err := conn.Read(ctx)
		require.NoError(t, err)
		messageLines := strings.Split(string(message), "\n")
		requireScrubbed(t, "websocket", string(message), func(i int) (string, bool) { return messageLines[i], true })
	})

	t.Run("a finished event is not held", func(t *testing.T) {
		// A server-sent event ends in a blank line, which cannot start a
		// match, so the proxy hands it over before the next one is written.
		resp := throughProxy(t, httpAddr, upstreamAddr, "/events")
		defer resp.Body.Close()
		defer close(release)
		// A client dispatches the event only at its blank line, so the whole
		// event, terminator included, must arrive.
		event := make(chan string, 1)
		go func() {
			reader := bufio.NewReader(resp.Body)
			line, _ := reader.ReadString('\n')
			blank, _ := reader.ReadString('\n')
			event <- line + blank
		}()
		select {
		case got := <-event:
			require.Equal(t, "data: {\"delta\":\"hi\"}\n\n", got)
		case <-time.After(2 * time.Second):
			t.Fatal("the proxy held a finished event waiting for more bytes")
		}
	})

	t.Run("a response without the value passes byte-identical", func(t *testing.T) {
		resp := throughProxy(t, httpAddr, upstreamAddr, "/plain")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.True(t, utf8.Valid(plain[len(plain)/2:]))
		require.Equal(t, len(plain), len(body))
		require.True(t, string(plain) == string(body), "body changed")
		require.Equal(t, "100%25 & \\u0041 &#65; \u200b", resp.Header.Get("X-Plain"))
	})

	t.Run("base64 wrapped across lines", func(t *testing.T) {
		resp := throughProxy(t, httpAddr, upstreamAddr, "/wrapped")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		text := unwrapped(string(body))
		for _, prefix := range []string{"", "u", "u:"} {
			stable := middle(base64.StdEncoding.EncodeToString, 6, prefix)
			require.NotContains(t, text, stable(reflectReal), "wrapped base64 after %q leaked", prefix)
			require.Contains(t, text, stable(reflectPlaceholder), "wrapped base64 after %q lost the placeholder", prefix)
		}
	})

	t.Run("a field name that carries a held value is refused", func(t *testing.T) {
		// Go canonicalizes a field name before the case-sensitive scrub, so
		// the name comes back case-folded; a lowercasing client recovers it.
		for _, path := range []string{"/header-name", "/header-name-reversed", "/header-name-rot13", "/trailer-name"} {
			resp := throughProxy(t, httpAddr, upstreamAddr, path)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.Equal(t, http.StatusBadGateway, resp.StatusCode, path)
			requireNoName(t, path, resp, string(body))
			require.NotContains(t, strings.ToLower(fmt.Sprint(resp.Header)), reversed(nameReal), path)
			require.NotContains(t, strings.ToLower(fmt.Sprint(resp.Header)), strings.ToLower(rot13(nameReal)), path)
		}
		// A trailer that arrives after the body ends the response unfinished.
		resp := throughProxy(t, httpAddr, upstreamAddr, "/trailer-late")
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Error(t, err, "the response ended as a whole one")
		requireNoName(t, "/trailer-late", resp, string(body))
	})

	t.Run("one gzip layer is decoded and scrubbed", func(t *testing.T) {
		resp := throughProxy(t, httpAddr, upstreamAddr, "/gzip-once")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "stored="+reflectPlaceholder, string(body))
	})

	t.Run("a compressed body is decoded once and scrubbed, or refused", func(t *testing.T) {
		// identity then gzip is one gzip layer, decoded and scrubbed.
		resp := throughProxy(t, httpAddr, upstreamAddr, "/gzip-two-lines")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, reflectPlaceholder, string(body))
		// A second layer, or compressed gRPC messages, cannot be read.
		for _, path := range []string{"/gzip-twice", "/grpc"} {
			resp := throughProxy(t, httpAddr, upstreamAddr, path)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.Equal(t, http.StatusBadGateway, resp.StatusCode, path)
			require.NotContains(t, gunzipAll(body), reflectReal, path)
		}
	})

	t.Run("a value split across websocket messages never arrives whole", func(t *testing.T) {
		for _, path := range []string{"/ws-split", "/ws-interleaved"} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, _, err := websocket.Dial(ctx, "ws://"+httpAddr+path, &websocket.DialOptions{
				Host:       upstreamAddr,
				HTTPHeader: http.Header{"Authorization": {"Bearer " + reflectPlaceholder}, "X-Api-Key": {namePlaceholder}},
			})
			require.NoError(t, err)
			var received, texts strings.Builder
			for {
				_, message, err := conn.Read(ctx)
				if err != nil {
					break
				}
				received.Write(message)
				var delta struct{ Type, Delta string }
				if json.Unmarshal(message, &delta) == nil && strings.HasSuffix(delta.Type, "transcript.delta") {
					texts.WriteString(delta.Delta)
				}
			}
			conn.CloseNow()
			cancel()
			require.NotContains(t, received.String()+texts.String(), reflectReal, path)
			require.NotContains(t, received.String(), "after", "%s: the relay went on after the split value", path)
		}
	})
}

// requireNoName checks no field name, value or body text carries the name
// value in any letter case.
func requireNoName(t *testing.T, surface string, resp *http.Response, body string) {
	t.Helper()
	var fields strings.Builder
	_ = resp.Header.Write(&fields)
	_ = resp.Trailer.Write(&fields)
	require.NotContains(t, strings.ToLower(fields.String()+body), nameReal, surface)
}

// gunzipAll undoes every gzip layer it finds, at the start of the body or
// after a gRPC message prefix.
func gunzipAll(body []byte) string {
	for range 4 {
		start := bytes.Index(body, []byte{0x1f, 0x8b})
		if start < 0 {
			break
		}
		reader, err := gzip.NewReader(bytes.NewReader(body[start:]))
		if err != nil {
			break
		}
		next, err := io.ReadAll(reader)
		if err != nil && len(next) == 0 {
			break
		}
		body = next
	}
	return string(body)
}
