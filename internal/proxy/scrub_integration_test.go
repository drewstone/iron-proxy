package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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
func middle(encoding *base64.Encoding, prefix string) func(string) string {
	return func(value string) string {
		encoded := encoding.EncodeToString([]byte(prefix + value))
		return encoded[(8*len(prefix)+5)/6 : 8*(len(prefix)+len(value))/6]
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
	}
	for _, enc := range []struct {
		name     string
		encoding *base64.Encoding
	}{
		{"base64", base64.StdEncoding}, {"base64 unpadded", base64.RawStdEncoding},
		{"base64url", base64.URLEncoding}, {"base64url unpadded", base64.RawURLEncoding},
	} {
		for _, prefix := range []string{"", "u:", "user:"} {
			rows = append(rows, reflection{
				name: fmt.Sprintf("%s after %q", enc.name, prefix),
				form: func(v string) string { return enc.encoding.EncodeToString([]byte(prefix + v)) },
				// The scrub can only replace the characters that depend on the
				// value alone, so that middle is what is asserted.
				placeholder: middle(enc.encoding, prefix),
				stable:      middle(enc.encoding, prefix),
			})
		}
	}
	return rows
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
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
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
`, reflectPlaceholder, scrub)), testLogger())
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
		event := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(resp.Body).ReadString('\n')
			event <- line
		}()
		select {
		case got := <-event:
			require.Equal(t, "data: {\"delta\":\"hi\"}\n", got)
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
}
