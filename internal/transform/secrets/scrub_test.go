package secrets

import (
	"encoding/base64"
	"io"
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
