package secrets

import (
	"bytes"
	"encoding/base64"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
)

const (
	scrubReal        = "hf_REAL0123456789abcdef0123456789abcdef"
	scrubPlaceholder = "proxy-declared-0-token.SALT"
)

// scrubInput carries the value every way a reflecting host can return it: bare,
// twice in a row, in a header line, as the password of HTTP Basic auth at each
// of the three base64 alignments, and as near misses that must pass through.
func scrubInput() []byte {
	var b strings.Builder
	b.WriteString(`{"authorization":"Bearer ` + scrubReal + `"}` + "\n")
	b.WriteString(scrubReal + scrubReal + "\n")
	b.WriteString("Authorization: Basic ")
	for _, user := range []string{"u:", "us:", "usr:"} {
		b.WriteString(base64.StdEncoding.EncodeToString([]byte(user+scrubReal)) + " ")
	}
	b.WriteString("\n")
	b.WriteString("near miss " + scrubReal[:len(scrubReal)-1] + "X and " + scrubReal[:7] + " alone\n")
	b.WriteString("ends in a prefix " + scrubReal[:12])
	return []byte(b.String())
}

func TestScrubRemovesTheValueWhereverTheStreamIsCut(t *testing.T) {
	pairs := scrubPairsFor(scrubReal, scrubPlaceholder)
	if len(pairs) != 4 {
		t.Fatalf("want the value and three base64 alignments, got %d pairs", len(pairs))
	}
	input := scrubInput()
	scrub := newScrubber(pairs)
	whole, _ := scrub.scan(input, true)

	for _, pair := range pairs[:1] {
		if bytes.Contains(whole, pair.needle) {
			t.Fatalf("the value survived: %s", whole)
		}
	}
	for _, pair := range pairs[1:] {
		if bytes.Contains(whole, pair.needle) {
			t.Fatalf("a base64 form survived: %s", whole)
		}
	}
	if got := bytes.Count(whole, []byte(scrubPlaceholder)); got != 3 {
		t.Fatalf("want 3 placeholders for the bare uses, got %d: %s", got, whole)
	}
	if !bytes.Contains(whole, []byte("near miss "+scrubReal[:len(scrubReal)-1]+"X")) ||
		!bytes.HasSuffix(whole, []byte("ends in a prefix "+scrubReal[:12])) {
		t.Fatalf("text that is not the value changed: %s", whole)
	}

	read := func(chunks [][]byte) []byte {
		pr, pw := io.Pipe()
		go func() {
			for _, chunk := range chunks {
				pw.Write(chunk)
			}
			pw.Close()
		}()
		out, err := io.ReadAll(newScrubReader(pr, pr, newScrubber(pairs)))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Every two-way cut, one-byte chunks, and random cuts give the same bytes.
	for cut := 0; cut <= len(input); cut++ {
		if got := read([][]byte{input[:cut], input[cut:]}); !bytes.Equal(got, whole) {
			t.Fatalf("cut at %d changed the output:\n got %s\nwant %s", cut, got, whole)
		}
	}
	singles := make([][]byte, len(input))
	for i := range input {
		singles[i] = input[i : i+1]
	}
	if got := read(singles); !bytes.Equal(got, whole) {
		t.Fatalf("one-byte chunks changed the output:\n got %s\nwant %s", got, whole)
	}
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 500; round++ {
		var chunks [][]byte
		for rest := input; len(rest) > 0; {
			n := 1 + rng.Intn(len(rest))
			chunks, rest = append(chunks, rest[:n]), rest[n:]
		}
		if got := read(chunks); !bytes.Equal(got, whole) {
			t.Fatalf("random cuts changed the output:\n got %s\nwant %s", got, whole)
		}
	}
}

func TestScrubReaderDoesNotHoldAFinishedEvent(t *testing.T) {
	// A server-sent event ends in a blank line, which cannot start the value,
	// so the reader must hand it over before the next one is written.
	pr, pw := io.Pipe()
	reader := newScrubReader(pr, pr, newScrubber(scrubPairsFor(scrubReal, scrubPlaceholder)))
	go pw.Write([]byte("data: {\"delta\":\"hi\"}\n\n"))

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := reader.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case event := <-got:
		if event != "data: {\"delta\":\"hi\"}\n\n" {
			t.Fatalf("event changed: %q", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the reader held a finished event waiting for more bytes")
	}
	pw.Close()
}
