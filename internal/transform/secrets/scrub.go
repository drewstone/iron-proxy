package secrets

import (
	"compress/gzip"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// The response scrub removes a held secret from everything a declared host
// sends back: headers, trailers, streamed bodies and WebSocket messages.
//
// It matches a value through the encodings an HTTP service commonly applies
// when it reflects one, and replaces each match with the placeholder in the
// same encoding. Two kinds of encoding are covered:
//
//   - Escapes that spell each character on its own, mixed freely within one
//     match: percent-encoding (either hex case), JSON escapes (\uXXXX in
//     either case, surrogate pairs, \" \\ \/ \b \f \n \r \t), \xNN, HTML
//     numeric references (decimal and hex) and the named references for
//     & < > " '. An ASCII character may be escaped twice, when an escape's
//     own '%', '&' or '\' is escaped again (a URL escaped twice, an HTML
//     reference inside JSON, JSON inside JSON). Unicode format characters
//     (category Cf, such as U+200B or U+FEFF), raw or escaped, may sit between
//     characters of a match; up to maxGap of them per gap are skipped and the
//     whole span is replaced.
//   - Transforms of the whole value, each matched through the escapes above:
//     hex (either case), base64 in the standard and URL alphabets at all three
//     alignments and base32 in the standard and hex alphabets (either case) at
//     all five (padded or not, since only the characters that depend on the
//     value alone are matched), the reversed value and rot13. Hex, base64 and
//     base32 may also be wrapped across lines: up to two line breaks (CR or LF,
//     raw or escaped) count as one gap.
//
// A response to a request that redeemed a canonical secret is also projected
// by its media type: a model stream that splits the value across records is
// matched in the decoded text of each lane, and a stream format that cannot
// be projected is refused (semantic.go).
//
// A value split across the messages of one WebSocket direction, or across the
// strings at one path of a protected JSON document (array positions aside),
// cannot be replaced once its first part is sent, so the connection or the
// response is refused before the rest of it.
//
// Residual risk: the scrub catches reflection in these known encodings. A
// declared host that applies any other reversible transform, such as
// encryption, compression it does not declare, a byte list, or splitting the
// value across responses or across fields that are not one lane, returns the
// value in a form no scrub can recognise; a prefix of a value shorter than the
// whole is not matched either. A declared host therefore sits inside the trust
// boundary: declare only hosts trusted with the value itself.

// minFragment is the shortest derived needle worth matching. A shorter run is
// as likely to be ordinary text as part of an encoded secret.
const minFragment = 8

// maxGap is how many format characters may separate two characters of a
// match. It bounds both the work per candidate and the bytes a stream holds.
const maxGap = 16

// maxToken is the longest encoding of one character the matcher reads: an
// HTML reference whose '&' is itself an escaped reference, such as
// "&#0000038;#1114111;" (a four-byte UTF-8 sequence percent-encoded and a JSON
// surrogate pair are 12).
const maxToken = 20

// maxBreaks is how many line breaks one gap of a wrapped needle may hold: a
// CRLF.
const maxBreaks = 2

// scrubPair is one thing to find in a response and what replaces it.
type scrubPair struct {
	needle []byte
	repl   []byte
	// fold matches ASCII letters in either case and writes the replacement in
	// the case the match used. Hex and base32 set it.
	fold bool
	// wrap admits line breaks between characters, as encoders that wrap their
	// output at a line length write them. Hex, base64 and base32 set it.
	wrap bool
}

// scrubPairsFor lists the forms of one secret a response must not carry, each
// with the same form of the placeholder.
func scrubPairsFor(realValue, placeholder string) []scrubPair {
	if realValue == "" {
		return nil
	}
	pairs := []scrubPair{{needle: []byte(realValue), repl: []byte(placeholder)}}
	derived := func(needle, repl string, fold, wrap bool) {
		if utf8.RuneCountInString(needle) < minFragment || repl == "" || needle == realValue {
			return
		}
		for _, p := range pairs {
			if string(p.needle) == needle {
				return
			}
		}
		pairs = append(pairs, scrubPair{needle: []byte(needle), repl: []byte(repl), fold: fold, wrap: wrap})
	}
	derived(hex.EncodeToString([]byte(realValue)), hex.EncodeToString([]byte(placeholder)), true, true)
	derived(reverse(realValue), reverse(placeholder), false, false)
	derived(rot13(realValue), rot13(placeholder), false, false)
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for pad := 0; pad < 3; pad++ {
			derived(fragment(enc.EncodeToString, 6, realValue, pad), fragment(enc.EncodeToString, 6, placeholder, pad), false, true)
		}
	}
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.HexEncoding} {
		encode := func(b []byte) string { return strings.ToLower(enc.EncodeToString(b)) }
		for pad := 0; pad < 5; pad++ {
			derived(fragment(encode, 5, realValue, pad), fragment(encode, 5, placeholder, pad), true, true)
		}
	}
	return pairs
}

func reverse(value string) string {
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

// fragment returns the text that depends on value alone when pad bytes of
// other data come before it in a stream encoded at bits per character.
// Base64 turns three bytes into four characters and base32 five into eight,
// so the same value encodes differently depending on where it starts; the
// characters that also carry a neighbour's bits, and any padding, are left
// out.
func fragment(encode func([]byte) string, bits int, value string, pad int) string {
	encoded := encode(append(make([]byte, pad), value...))
	start := (8*pad + bits - 1) / bits
	end := 8 * (pad + len(value)) / bits
	if end <= start {
		return ""
	}
	return encoded[start:end]
}

// form is how one character was spelled in a response.
type form uint8

const (
	formLiteral form = iota
	formPercent
	formJSONU
	formJSONShort
	formHexEscape
	formHTMLDec
	formHTMLHex
	formHTMLNamed
)

// spelling is a form plus the hex case it used: 0 when it had no hex letter,
// 'a' for lower, 'A' for upper. outer, when not formLiteral, is how the
// escape's own first byte ('%', '&' or '\\') was escaped again.
type spelling struct {
	form      form
	hexCase   byte
	outer     form
	outerCase byte
}

// needle is a scrubPair decoded to characters. Bytes that are not UTF-8 decode
// to runes above unicode.MaxRune, so any byte string matches itself.
type needle struct {
	runes []rune
	repl  []rune
	fold  bool
	wrap  bool
	// literalEscape is set when the needle itself holds a character that
	// starts an escape, so a literal reading must also be tried.
	literalEscape bool
}

// scrubber replaces every needle, in any spelling, with its replacement.
type scrubber struct {
	needles []needle
	// ascii and other map a needle's first character to the needles that
	// start with it.
	ascii [utf8.RuneSelf][]int
	other map[rune][]int
	// start marks the bytes that can begin a needle's first character, and
	// pair the byte pairs that can begin a match, so most bytes are passed
	// over without decoding.
	start [256]bool
	pair  [256][4]uint64
}

func (s *scrubber) setPair(b0, b1 byte) { s.pair[b0][b1>>6] |= 1 << (b1 & 63) }

// setRow admits b0 followed by any byte.
func (s *scrubber) setRow(b0 byte) {
	s.pair[b0] = [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
}

func (s *scrubber) mayStart(data []byte, i int) bool {
	if i+1 == len(data) {
		return s.start[data[i]]
	}
	b1 := data[i+1]
	return s.pair[data[i]][b1>>6]&(1<<(b1&63)) != 0
}

func newScrubber(pairs []scrubPair) *scrubber {
	s := &scrubber{other: map[rune][]int{}}
	for _, b := range []byte{'%', '\\', '&'} {
		s.start[b] = true
		s.setRow(b)
	}
	for _, p := range pairs {
		n := needle{runes: decodeRunes(p.needle), repl: decodeRunes(p.repl), fold: p.fold, wrap: p.wrap}
		if len(n.runes) == 0 {
			continue
		}
		n.literalEscape = slices.ContainsFunc(n.runes, func(r rune) bool { return r == '%' || r == '\\' || r == '&' })
		index := len(s.needles)
		s.needles = append(s.needles, n)
		heads := []rune{n.runes[0]}
		if n.fold && unicode.ToUpper(n.runes[0]) != n.runes[0] {
			heads = append(heads, unicode.ToUpper(n.runes[0]))
		}
		for _, head := range heads {
			lead := appendRune(nil, head)[0]
			if head < utf8.RuneSelf {
				s.ascii[head] = append(s.ascii[head], index)
			} else {
				s.other[head] = append(s.other[head], index)
			}
			s.start[lead] = true
			if head >= utf8.RuneSelf || len(n.runes) == 1 || n.runes[1] >= utf8.RuneSelf {
				s.setRow(lead)
				continue
			}
			// The second character follows literally, escaped, after a line
			// break of a wrapped needle, or after a format character; the last
			// two start with a non-letter byte.
			for _, b1 := range []byte{byte(n.runes[1]), byte(unicode.ToUpper(n.runes[1])), '%', '\\', '&'} {
				s.setPair(lead, b1)
			}
			if n.wrap {
				s.setPair(lead, '\r')
				s.setPair(lead, '\n')
			}
			for b1 := utf8.RuneSelf; b1 < 256; b1++ {
				s.setPair(lead, byte(b1))
			}
		}
	}
	return s
}

func (s *scrubber) startingWith(r rune) []int {
	if r >= 0 && r < utf8.RuneSelf {
		return s.ascii[r]
	}
	return s.other[r]
}

func decodeRunes(b []byte) []rune {
	runes := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, w := utf8.DecodeRune(b)
		if r == utf8.RuneError && w <= 1 {
			r = unicode.MaxRune + 1 + rune(b[0])
			w = 1
		}
		runes = append(runes, r)
		b = b[w:]
	}
	return runes
}

func appendRune(dst []byte, r rune) []byte {
	if r > unicode.MaxRune {
		return append(dst, byte(r-unicode.MaxRune-1))
	}
	return utf8.AppendRune(dst, r)
}

// token status
const (
	tokenOK = iota
	tokenMore
)

// readToken decodes the character spelled at the start of data. escaped
// selects whether escapes are read, an ASCII character escaped twice
// included; when false, or when data starts with no escape, the character is
// the literal UTF-8 rune. tokenMore means data ends inside what may be a
// longer spelling and final is not set.
func readToken(data []byte, escaped, final bool) (rune, int, spelling, int) {
	r, w, sp, st := readSingle(data, escaped, final)
	if st != tokenOK || sp.form == formLiteral || !isEscapeStart(byte(r)) || r >= utf8.RuneSelf {
		return r, w, sp, st
	}
	// The escape spelled '%', '&' or '\\': it may start a second escape whose
	// remaining bytes follow it, as when an escaped value is escaped again.
	var buf [maxToken]byte
	buf[0] = byte(r)
	n := copy(buf[1:], data[w:])
	inner, iw, isp, more := readEscape(buf[:1+n])
	switch {
	case more && 1+n == len(buf):
		// Longer than any second escape this reads.
	case more && !final:
		return 0, 0, spelling{}, tokenMore
	case iw > 1 && inner < utf8.RuneSelf && isp.form != formLiteral:
		isp.outer, isp.outerCase = sp.form, sp.hexCase
		return inner, w + iw - 1, isp, tokenOK
	}
	return r, w, sp, st
}

// readEscape reads the escape at the start of data, if any.
func readEscape(data []byte) (r rune, w int, sp spelling, more bool) {
	switch data[0] {
	case '%':
		return readPercent(data)
	case '\\':
		return readBackslash(data)
	case '&':
		return readReference(data)
	}
	return 0, 0, spelling{}, false
}

// readSingle is readToken reading at most one layer of escape.
func readSingle(data []byte, escaped, final bool) (rune, int, spelling, int) {
	if escaped {
		r, w, sp, more := readEscape(data)
		if more && !final {
			return 0, 0, spelling{}, tokenMore
		}
		if w > 0 {
			return r, w, sp, tokenOK
		}
	}
	if !final && !utf8.FullRune(data) {
		return 0, 0, spelling{}, tokenMore
	}
	r, w := utf8.DecodeRune(data)
	if r == utf8.RuneError && w <= 1 {
		r, w = unicode.MaxRune+1+rune(data[0]), 1
	}
	return r, w, spelling{}, tokenOK
}

func hexValue(b byte) (int, byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), 0, true
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10, 'a', true
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10, 'A', true
	}
	return 0, 0, false
}

// readHex reads n hex digits. more reports that data ended before n digits
// with every digit so far valid.
func readHex(data []byte, n int) (value int, hexCase byte, ok, more bool) {
	for i := 0; i < n; i++ {
		if i >= len(data) {
			return 0, 0, false, true
		}
		digit, c, valid := hexValue(data[i])
		if !valid {
			return 0, 0, false, false
		}
		value = value<<4 | digit
		if c != 0 && hexCase == 0 {
			hexCase = c
		}
	}
	return value, hexCase, true, false
}

// readPercent reads %XX, joining the escaped bytes of one UTF-8 sequence.
func readPercent(data []byte) (rune, int, spelling, bool) {
	var buf [utf8.UTFMax]byte
	var hexCase byte
	need := 1
	for i := 0; i < need; i++ {
		at := 3 * i
		if at >= len(data) {
			return 0, 0, spelling{}, true
		}
		if data[at] != '%' {
			break
		}
		value, c, ok, more := readHex(data[at+1:], 2)
		if more {
			return 0, 0, spelling{}, true
		}
		if !ok {
			break
		}
		if hexCase == 0 {
			hexCase = c
		}
		buf[i] = byte(value)
		if i == 0 {
			switch {
			case value < 0x80:
			case value>>5 == 0x6:
				need = 2
			case value>>4 == 0xE:
				need = 3
			case value>>3 == 0x1E:
				need = 4
			}
		}
		if i == need-1 {
			r, w := utf8.DecodeRune(buf[:need])
			if r == utf8.RuneError && w <= 1 {
				break
			}
			return r, 3 * need, spelling{form: formPercent, hexCase: hexCase}, false
		}
	}
	// One escaped byte that does not complete a UTF-8 sequence stands for
	// itself, as a raw byte would.
	value, c, ok, _ := readHex(data[1:], 2)
	if !ok {
		return 0, 0, spelling{}, false
	}
	r := rune(value)
	if value >= 0x80 {
		r = unicode.MaxRune + 1 + r
	}
	return r, 3, spelling{form: formPercent, hexCase: c}, false
}

var jsonShort = map[byte]rune{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

// readBackslash reads \uXXXX (with surrogate pairs), \xNN and the short JSON
// escapes.
func readBackslash(data []byte) (rune, int, spelling, bool) {
	if len(data) < 2 {
		return 0, 0, spelling{}, true
	}
	switch data[1] {
	case 'u':
		unit, c, ok, more := readHex(data[2:], 4)
		if !ok {
			return 0, 0, spelling{}, more
		}
		r := rune(unit)
		if r >= 0xD800 && r < 0xDC00 {
			if len(data) < 8 || (data[6] == '\\' && len(data) < 12) {
				return 0, 0, spelling{}, true
			}
			if data[6] == '\\' && data[7] == 'u' {
				low, c2, ok, _ := readHex(data[8:], 4)
				if ok && low >= 0xDC00 && low < 0xE000 {
					if c == 0 {
						c = c2
					}
					return 0x10000 + (r-0xD800)<<10 + rune(low-0xDC00), 12, spelling{form: formJSONU, hexCase: c}, false
				}
			}
		}
		return r, 6, spelling{form: formJSONU, hexCase: c}, false
	case 'x':
		value, c, ok, more := readHex(data[2:], 2)
		if !ok {
			return 0, 0, spelling{}, more
		}
		return rune(value), 4, spelling{form: formHexEscape, hexCase: c}, false
	}
	if r, ok := jsonShort[data[1]]; ok {
		return r, 2, spelling{form: formJSONShort, hexCase: 0}, false
	}
	return 0, 0, spelling{}, false
}

var namedRefs = map[string]rune{"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\''}

// readReference reads an HTML character reference: &#DDD;, &#xHH; or one of
// the named references html.EscapeString writes.
func readReference(data []byte) (rune, int, spelling, bool) {
	if len(data) < 2 {
		return 0, 0, spelling{}, true
	}
	if data[1] != '#' {
		for i := 1; i < len(data) && i <= 5; i++ {
			if data[i] == ';' {
				r, ok := namedRefs[string(data[1:i])]
				if !ok {
					return 0, 0, spelling{}, false
				}
				return r, i + 1, spelling{form: formHTMLNamed, hexCase: 0}, false
			}
			if data[i] < 'a' || data[i] > 'z' {
				return 0, 0, spelling{}, false
			}
		}
		return 0, 0, spelling{}, len(data) <= 5
	}
	// Seven decimal or six hex digits spell any code point; longer runs, such
	// as extra leading zeros, are not read, which keeps a match bounded.
	digits, base, maxDigits, f := 2, 10, 7, formHTMLDec
	if len(data) > 2 && (data[2] == 'x' || data[2] == 'X') {
		digits, base, maxDigits, f = 3, 16, 6, formHTMLHex
	}
	var hexCase byte
	value := 0
	for i := digits; i < len(data); i++ {
		if data[i] == ';' {
			if i == digits || value > unicode.MaxRune {
				return 0, 0, spelling{}, false
			}
			return rune(value), i + 1, spelling{form: f, hexCase: hexCase}, false
		}
		if i-digits >= maxDigits {
			return 0, 0, spelling{}, false
		}
		digit, c, ok := hexValue(data[i])
		if !ok || (base == 10 && digit > 9) || (base == 10 && c != 0) {
			return 0, 0, spelling{}, false
		}
		if c != 0 && hexCase == 0 {
			hexCase = c
		}
		value = value*base + digit
	}
	return 0, 0, spelling{}, true
}

// isGap reports a character that may sit unseen inside a match. U+00AD is
// the first format character.
func isGap(r rune) bool {
	return r >= 0xAD && r <= unicode.MaxRune && unicode.Is(unicode.Cf, r)
}

func isEscapeStart(b byte) bool {
	return b == '%' || b == '\\' || b == '&'
}

const (
	matchNone = iota
	matchFound
	matchMore
)

// matchAt matches n at data[i:]. It returns the end of the match and the
// spelling of each character. escaped prefers reading an escape where one
// starts; the caller tries the other reading when this one fails, so a value
// that holds a literal "%41" or "&#65;" still matches itself.
func (s *scrubber) matchAt(data []byte, i int, n *needle, escaped, final bool, spellings []spelling) (int, []spelling, int) {
	spellings = spellings[:0]
	at := i
	for k, want := range n.runes {
		breaks := 0
		for gap := 0; ; gap++ {
			if at >= len(data) {
				if final {
					return 0, spellings, matchNone
				}
				return 0, spellings, matchMore
			}
			r, w, sp, st := rune(data[at]), 1, spelling{}, tokenOK
			if r >= utf8.RuneSelf || isEscapeStart(data[at]) {
				r, w, sp, st = readToken(data[at:], escaped, final)
				if st == tokenMore {
					return 0, spellings, matchMore
				}
			}
			if equalRune(r, want, n.fold) {
				spellings = append(spellings, letterCase(sp, r, want, n.fold))
				at += w
				break
			}
			// One layer of escape, then the literal byte, is tried when the
			// longest reading does not spell the wanted character.
			if escaped && w > 1 && sp.form != formLiteral {
				if fr, fw, fsp, ok := fallbackToken(data[at:], sp, want, n.fold, final); ok {
					spellings = append(spellings, letterCase(fsp, fr, want, n.fold))
					at += fw
					break
				}
			}
			if r == '\r' || r == '\n' {
				breaks++
			}
			if k == 0 || gap >= maxGap || !(isGap(r) || (n.wrap && breaks > 0 && breaks <= maxBreaks && (r == '\r' || r == '\n'))) {
				return 0, spellings, matchNone
			}
			at += w
		}
	}
	return at, spellings, matchFound
}

// letterCase records, for a needle matched in either case, the case a letter
// was written in, which its replacement keeps.
func letterCase(sp spelling, got, want rune, fold bool) spelling {
	if fold && got != want {
		sp.hexCase = 'A'
	} else if fold && unicode.IsLetter(got) {
		sp.hexCase = 'a'
	}
	return sp
}

// fallbackToken reads the token at data as one layer of escape, when the
// longest reading was two, and then as the literal byte, returning the first
// reading that spells want.
func fallbackToken(data []byte, longest spelling, want rune, fold, final bool) (rune, int, spelling, bool) {
	if longest.outer != formLiteral {
		if r, w, sp, st := readSingle(data, true, final); st == tokenOK && equalRune(r, want, fold) {
			return r, w, sp, true
		}
	}
	r, w, sp, _ := readSingle(data, false, true)
	return r, w, sp, equalRune(r, want, fold)
}

func equalRune(got, want rune, fold bool) bool {
	return got == want || (fold && got < utf8.RuneSelf && want < utf8.RuneSelf && unicode.ToLower(got) == want)
}

// encodeRepl writes n's replacement spelled as the match was. A character of
// the replacement that also occurs in the match takes its spelling; any other
// takes the spelling of the match's first character of the same class
// (letters and digits, the unreserved punctuation -._~, everything else), so
// an escaper that leaves a class alone leaves it alone in the replacement too.
func encodeRepl(dst []byte, n *needle, spellings []spelling) []byte {
	var byClass [3]*spelling
	byRune := map[rune]spelling{}
	caseOf := map[form]byte{}
	for k, sp := range spellings {
		r := n.runes[k]
		if _, seen := byRune[r]; !seen {
			byRune[r] = sp
		}
		if c := class(r); byClass[c] == nil {
			byClass[c] = &spellings[k]
		}
		if sp.hexCase != 0 && caseOf[sp.form] == 0 {
			caseOf[sp.form] = sp.hexCase
		}
	}
	for _, r := range n.repl {
		sp, ok := byRune[r]
		if !ok {
			sp = spellings[0]
			for _, c := range []int{class(r), 0} {
				if byClass[c] != nil {
					sp = *byClass[c]
					break
				}
			}
		}
		hexCase := caseOf[sp.form]
		if n.fold && hexCase == 'A' {
			r = unicode.ToUpper(r)
		}
		if sp.outer == formLiteral {
			dst = spell(dst, r, sp.form, hexCase)
			continue
		}
		// Escaped twice: the escape's first byte is escaped again as the
		// match's was.
		inner := spell(nil, r, sp.form, hexCase)
		if len(inner) > 1 && isEscapeStart(inner[0]) {
			dst = append(spell(dst, rune(inner[0]), sp.outer, sp.outerCase), inner[1:]...)
		} else {
			dst = append(dst, inner...)
		}
	}
	return dst
}

func class(r rune) int {
	switch {
	case r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)):
		return 0
	case r == '-' || r == '.' || r == '_' || r == '~':
		return 1
	}
	return 2
}

func spell(dst []byte, r rune, f form, hexCase byte) []byte {
	digits := "0123456789ABCDEF"
	if hexCase == 'a' {
		digits = "0123456789abcdef"
	}
	hexByte := func(dst []byte, b byte) []byte { return append(dst, digits[b>>4], digits[b&0xF]) }
	switch f {
	case formPercent:
		for _, b := range appendRune(nil, r) {
			dst = hexByte(append(dst, '%'), b)
		}
		return dst
	case formJSONU:
		if r > unicode.MaxRune {
			break
		}
		units := []rune{r}
		if r >= 0x10000 {
			r -= 0x10000
			units = []rune{0xD800 + r>>10, 0xDC00 + r&0x3FF}
		}
		for _, u := range units {
			dst = hexByte(hexByte(append(dst, '\\', 'u'), byte(u>>8)), byte(u))
		}
		return dst
	case formJSONShort:
		for b, short := range jsonShort {
			if short == r {
				return append(dst, '\\', b)
			}
		}
	case formHexEscape:
		if r < 0x80 {
			return hexByte(append(dst, '\\', 'x'), byte(r))
		}
	case formHTMLDec:
		if r <= unicode.MaxRune {
			return append(strconv.AppendInt(append(dst, '&', '#'), int64(r), 10), ';')
		}
	case formHTMLHex:
		if r <= unicode.MaxRune {
			text := strconv.FormatInt(int64(r), 16)
			if hexCase == 'A' {
				text = strings.ToUpper(text)
			}
			return append(append(append(dst, '&', '#', 'x'), text...), ';')
		}
	case formHTMLNamed:
		for name, named := range namedRefs {
			if named == r {
				return append(append(append(dst, '&'), name...), ';')
			}
		}
	}
	return appendRune(dst, r)
}

// scan appends data to dst with every needle replaced. Unless final, the
// trailing held bytes of data may be the start of a match that the next bytes
// finish: they are not in out, and the caller carries them into the next
// scan. A match of an n-character needle spans at most
// n*maxToken + (n-1)*maxGap*maxToken bytes, which bounds held: 15,999 bytes
// for a 48-character secret.
func (s *scrubber) scan(dst, data []byte, final bool) (out []byte, held int) {
	out, held, _ = s.scanFenced(dst, data, final, 0)
	return out, held
}

// scanFenced is scan for data whose first fence bytes were already sent: they
// are not written to out and a match inside them is left as it was, while a
// match that starts inside them and ends after them reports crossed, since its
// first part can no longer be replaced.
func (s *scrubber) scanFenced(dst, data []byte, final bool, fence int) (out []byte, held int, crossed bool) {
	out = dst
	emitted := 0
	emit := func(to int) {
		if from := max(emitted, fence); to > from {
			out = append(out, data[from:to]...)
		}
	}
	var spellings, best []spelling
	for i := 0; i < len(data); i++ {
		for i < len(data) && !s.mayStart(data, i) {
			i++
		}
		if i == len(data) {
			break
		}
		bestEnd, bestNeedle, more := -1, -1, false
		// Where an escape starts, each reading is tried: the longest escape,
		// one layer of it when it was two, and the literal byte for a needle
		// that itself holds that byte.
		passes := 1
		if isEscapeStart(data[i]) {
			passes = 3
		}
		var longest spelling
		for pass := 0; pass < passes; pass++ {
			escaped := pass < 2
			r, w, sp, st := rune(data[i]), 1, spelling{}, tokenOK
			switch {
			case pass == 1 && longest.outer == formLiteral:
				continue
			case pass == 1:
				r, w, sp, st = readSingle(data[i:], true, final)
			case r >= utf8.RuneSelf || isEscapeStart(data[i]):
				r, w, sp, st = readToken(data[i:], escaped, final)
			}
			if pass == 0 {
				longest = sp
			}
			if st == tokenMore {
				more = true
				continue
			}
			// The next byte, when it is plain ASCII, decides most candidates
			// without a full match attempt.
			var next byte
			if i+w < len(data) && data[i+w] < utf8.RuneSelf && !isEscapeStart(data[i+w]) {
				next = data[i+w]
			}
			for _, index := range s.startingWith(r) {
				n := &s.needles[index]
				if (!escaped && !n.literalEscape) || (next != 0 && len(n.runes) > 1 && !equalRune(rune(next), n.runes[1], n.fold) &&
					!(n.wrap && (next == '\r' || next == '\n'))) {
					continue
				}
				end, sp, result := s.matchAt(data, i, n, escaped, final, spellings)
				spellings = sp
				switch result {
				case matchMore:
					more = true
				case matchFound:
					if end > bestEnd {
						bestEnd, bestNeedle = end, index
						best = append(best[:0], sp...)
					}
				}
			}
			if bestNeedle >= 0 {
				break
			}
		}
		if more {
			// A longer match may still complete; hold from here.
			emit(i)
			return out, len(data) - i, false
		}
		if bestNeedle < 0 {
			continue
		}
		if i < fence {
			if bestEnd > fence {
				return out, 0, true
			}
			// Sent already, and replaced then if the scan saw it whole.
			emitted = bestEnd
			i = bestEnd - 1
			continue
		}
		emit(i)
		out = encodeRepl(out, &s.needles[bestNeedle], best)
		emitted = bestEnd
		i = bestEnd - 1
	}
	emit(len(data))
	return out, 0, false
}

func (s *scrubber) text(value string) string {
	out, _ := s.scan(nil, []byte(value), true)
	return string(out)
}

// scrubReader scrubs a body as it streams. It delivers what it has as soon as
// it can prove no match starts in it, so a stream that pauses is held back
// only by the bytes that begin a match, bounded as scan states. Memory is one
// 32 KiB read plus that held tail. project is the scan, or for a protected
// response the projection of its media type (semantic.go).
type scrubReader struct {
	src     io.Reader
	closer  io.Closer
	project func(dst, data []byte, final bool) ([]byte, int, error)
	// strict sends the held tail only at a clean end of stream: a failed or
	// refused protected stream drops it and ends with ErrResponseRefused.
	strict  bool
	chunk   []byte
	pending []byte
	out     []byte
	ready   []byte
	done    bool
	err     error
}

func newScrubReader(src io.Reader, closer io.Closer, s *scrubber) *scrubReader {
	scan := func(dst, data []byte, final bool) ([]byte, int, error) {
		out, held := s.scan(dst, data, final)
		return out, held, nil
	}
	return &scrubReader{src: src, closer: closer, project: scan, chunk: make([]byte, 32<<10)}
}

func (r *scrubReader) Read(p []byte) (int, error) {
	for len(r.ready) == 0 {
		if r.done {
			return 0, r.err
		}
		n, err := r.src.Read(r.chunk)
		r.pending = append(r.pending, r.chunk[:n]...)
		if err != nil && err != io.EOF && r.strict {
			// A protected body that fails to read ends as a refusal, which
			// the proxy aborts, and drops what it holds; the cause is not
			// passed on.
			r.pending, r.done, r.err = nil, true, ErrResponseRefused
			continue
		}
		out, held, refused := r.project(r.out[:0], r.pending, err != nil)
		if refused != nil {
			r.pending, r.done, r.err = nil, true, refused
			continue
		}
		r.out, r.ready = out, out
		if held < len(r.pending) {
			// Moving a tail that is all of pending would copy it onto itself on
			// every read, which small reads make quadratic.
			r.pending = append(r.pending[:0], r.pending[len(r.pending)-held:]...)
		}
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

	// Trailer names declared up front are checked here too; one that arrives
	// only with the trailers is checked when it is written (MaskResponseFieldName).
	if refuseCredentialHeaderNames(resp.Header, scrub, state.values) || refuseCredentialHeaderNames(resp.Trailer, scrub, state.values) {
		return refuseResponse(tctx, req, names, "response_header_name", "response header name cannot be checked for a held secret\n"), nil
	}

	scrubHeaders(resp.Header, scrub)

	if req.Method == http.MethodHead || resp.ContentLength == 0 ||
		resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	// Bytes the proxy cannot read as text cannot be scrubbed. The request
	// asked for gzip itself, so net/http decodes nothing and every coding is
	// seen here: one gzip layer is decoded below; any other coding or a second
	// layer on any line, or gRPC or Connect message compression, is refused.
	gzipped, ok := bodyCoding(resp.Header)
	if !ok {
		return refuseResponse(tctx, req, names, "response_encoding", "response encoding cannot be checked for a held secret\n"), nil
	}

	// Read the upstream stream directly: the buffered body would hold the
	// whole response in memory first.
	body := transform.RequireBufferedBody(resp.Body)
	stream := body.StreamingReader()
	if gzipped {
		stream = &gunzipReader{src: stream}
		resp.Header.Del("Content-Encoding")
		resp.Uncompressed = true
	}
	closer, _ := stream.(io.Closer)
	if closer == nil {
		closer = body
	}
	var reader *scrubReader
	if len(state.canonical) == 0 {
		reader = newScrubReader(stream, closer, scrub)
	} else {
		var mode string
		reader, mode = protectedBody(resp, stream, closer, scrub)
		tctx.Annotate("secret_response_mode", mode)
		if reader == nil {
			return refuseResponse(tctx, req, names, "response_mode", "response type cannot be checked for a held secret\n"), nil
		}
	}
	resp.Body = transform.NewBufferedBody(reader, 0)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// bodyCoding reads every line of every field that names a coding of the body
// or its messages. gzipped reports one gzip layer on the body; ok is false
// for any other coding, a second layer, or compressed gRPC or Connect
// messages.
func bodyCoding(header http.Header) (gzipped, ok bool) {
	var codings []string
	for _, field := range []string{"Content-Encoding", "Grpc-Encoding", "Connect-Content-Encoding"} {
		for _, line := range header.Values(field) {
			for _, coding := range strings.Split(line, ",") {
				if coding = strings.TrimSpace(coding); coding != "" && !strings.EqualFold(coding, "identity") {
					codings = append(codings, field+":"+strings.ToLower(coding))
				}
			}
		}
	}
	switch {
	case len(codings) == 0:
		return false, true
	case len(codings) == 1 && (codings[0] == "Content-Encoding:gzip" || codings[0] == "Content-Encoding:x-gzip"):
		return true, true
	}
	return false, false
}

// askGzip makes a request whose response will be scrubbed ask for gzip or no
// coding, and for uncompressed messages. With Accept-Encoding set, net/http
// neither adds its own nor decodes a reply, which would hide the coding of a
// second layer beneath; the scrub decodes the one layer itself.
func askGzip(req *http.Request) {
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Del("Grpc-Accept-Encoding")
	req.Header.Del("Connect-Accept-Encoding")
}

// gunzipReader decodes one gzip layer, starting at the first read so that
// TransformResponse does not wait on the body.
type gunzipReader struct {
	src    io.Reader
	reader *gzip.Reader
	err    error
}

func (g *gunzipReader) Read(p []byte) (int, error) {
	if g.reader == nil && g.err == nil {
		g.reader, g.err = gzip.NewReader(g.src)
	}
	if g.err != nil {
		return 0, g.err
	}
	return g.reader.Read(p)
}

// refuseResponse replaces a response the scrub cannot check with a 502 that
// carries none of it.
func refuseResponse(tctx *transform.TransformContext, req *http.Request, names []string, reason, message string) *transform.TransformResult {
	tctx.Annotate("rejected", names)
	tctx.Annotate("reject_reason", reason)
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode:    http.StatusBadGateway,
			Status:        "502 Bad Gateway",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          transform.NewBufferedBodyFromBytes([]byte(message)),
			ContentLength: int64(len(message)),
			Request:       req,
		},
	}
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

func requestState(req *http.Request) *requestScrubs {
	if req == nil {
		return nil
	}
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	return state
}

// MaskResponseText uses only this request's selected source values, including after rotation.
func MaskResponseText(req *http.Request, value string) string {
	state := requestState(req)
	if state == nil {
		return value
	}
	return newScrubber(state.pairs).text(value)
}

// MaskResponseFieldName masks a response field name, such as a trailer's that
// arrives after the body. ok is false when the name carries a held value in
// any letter case: Go canonicalizes field names before the case-sensitive
// scrub sees them, so the response must be ended instead.
func MaskResponseFieldName(req *http.Request, name string) (masked string, ok bool) {
	state := requestState(req)
	if state == nil {
		return name, true
	}
	scrub := newScrubber(state.pairs)
	if refuseCredentialHeaderNames(http.Header{name: nil}, scrub, state.values) {
		return "", false
	}
	return scrub.text(name), true
}

// MessageMask scrubs the messages of one direction of a WebSocket. A message
// is delivered whole when it ends, so a match cannot be held across messages;
// instead the end of each message that may begin a match is kept, and a
// message that would complete it ends the relay with ErrResponseRefused
// before the bytes that complete it are sent. The strings of text messages
// that are JSON are fenced the same way, one lane for each place in a message
// (array positions aside) across all messages, as a protected JSON document's
// are. Memory is one 32 KiB read plus those tails, bounded as scan's held
// bytes.
type MessageMask struct {
	scrub *scrubber
	carry []byte
	chunk []byte
	split *splitFence
}

// NewMessageMask returns nil when the request holds nothing to scrub.
func NewMessageMask(req *http.Request) *MessageMask {
	state := requestState(req)
	if state == nil || len(state.pairs) == 0 {
		return nil
	}
	scrub := newScrubber(state.pairs)
	return &MessageMask{scrub: scrub, chunk: make([]byte, 32<<10), split: newSplitFence(scrub)}
}

// Reader scrubs one message; read each to its end before the next.
func (m *MessageMask) Reader(src io.Reader, text bool) io.Reader {
	if text {
		src = newJSONMessageReader(src, m.split)
	}
	fence := len(m.carry)
	r := &scrubReader{src: src, chunk: m.chunk, pending: append([]byte(nil), m.carry...), strict: true}
	r.project = func(dst, data []byte, final bool) ([]byte, int, error) {
		out, held, crossed := m.scrub.scanFenced(dst, data, false, fence)
		if !crossed && final {
			// The message ends: what may begin a match is sent too, with
			// every match it completes replaced, and kept to fence the next.
			tail := data[len(data)-held:]
			fence = max(0, fence-(len(data)-held))
			out, _, crossed = m.scrub.scanFenced(out, tail, true, fence)
			m.carry = append(m.carry[:0], tail...)
			held = 0
		}
		if crossed {
			return dst, 0, ErrResponseRefused
		}
		fence = max(0, fence-(len(data)-held))
		return out, held, nil
	}
	return r
}
