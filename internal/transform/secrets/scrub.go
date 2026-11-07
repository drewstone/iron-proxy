package secrets

import (
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
//     & < > " '. Unicode format characters (category Cf, such as U+200B or
//     U+FEFF), raw or escaped, may sit between characters of a match; up to
//     maxGap of them per gap are skipped and the whole span is replaced.
//   - Transforms of the whole value, each matched through the escapes above:
//     hex (either case), base64 in the standard and URL alphabets at all three
//     alignments and base32 in the standard and hex alphabets (either case) at
//     all five (padded or not, since only the characters that depend on the
//     value alone are matched), the reversed value and rot13.
//
// A response to a request that redeemed a canonical secret is also projected
// by its media type: a model stream that splits the value across records is
// matched in the decoded text of each lane, and a stream format that cannot
// be projected is refused (semantic.go).
//
// Residual risk: the scrub catches reflection in these known encodings. A
// declared host that applies any other reversible transform, such as
// encryption, compression, splitting the value across responses or fields
// that are not one lane, or base64 wrapped across lines, returns the value in
// a form no scrub can recognise. A declared host therefore sits inside the
// trust boundary: declare only hosts trusted with the value itself.

// minFragment is the shortest derived needle worth matching. A shorter run is
// as likely to be ordinary text as part of an encoded secret.
const minFragment = 8

// maxGap is how many format characters may separate two characters of a
// match. It bounds both the work per candidate and the bytes a stream holds.
const maxGap = 16

// maxToken is the longest encoding of one character the matcher reads: a
// four-byte UTF-8 sequence percent-encoded, or a JSON surrogate pair.
const maxToken = 12

// scrubPair is one thing to find in a response and what replaces it.
type scrubPair struct {
	needle []byte
	repl   []byte
	// fold matches ASCII letters in either case and writes the replacement in
	// the case the match used. Hex and base32 set it.
	fold bool
}

// scrubPairsFor lists the forms of one secret a response must not carry, each
// with the same form of the placeholder.
func scrubPairsFor(realValue, placeholder string) []scrubPair {
	if realValue == "" {
		return nil
	}
	pairs := []scrubPair{{needle: []byte(realValue), repl: []byte(placeholder)}}
	derived := func(needle, repl string, fold bool) {
		if utf8.RuneCountInString(needle) < minFragment || repl == "" || needle == realValue {
			return
		}
		for _, p := range pairs {
			if string(p.needle) == needle {
				return
			}
		}
		pairs = append(pairs, scrubPair{needle: []byte(needle), repl: []byte(repl), fold: fold})
	}
	derived(hex.EncodeToString([]byte(realValue)), hex.EncodeToString([]byte(placeholder)), true)
	derived(reverse(realValue), reverse(placeholder), false)
	derived(rot13(realValue), rot13(placeholder), false)
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for pad := 0; pad < 3; pad++ {
			derived(fragment(enc.EncodeToString, 6, realValue, pad), fragment(enc.EncodeToString, 6, placeholder, pad), false)
		}
	}
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.HexEncoding} {
		encode := func(b []byte) string { return strings.ToLower(enc.EncodeToString(b)) }
		for pad := 0; pad < 5; pad++ {
			derived(fragment(encode, 5, realValue, pad), fragment(encode, 5, placeholder, pad), true)
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
// 'a' for lower, 'A' for upper.
type spelling struct {
	form    form
	hexCase byte
}

// needle is a scrubPair decoded to characters. Bytes that are not UTF-8 decode
// to runes above unicode.MaxRune, so any byte string matches itself.
type needle struct {
	runes []rune
	repl  []rune
	fold  bool
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
		n := needle{runes: decodeRunes(p.needle), repl: decodeRunes(p.repl), fold: p.fold}
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
			// The second character follows literally, escaped, or after a
			// format character; the last two start with a non-letter byte.
			for _, b1 := range []byte{byte(n.runes[1]), byte(unicode.ToUpper(n.runes[1])), '%', '\\', '&'} {
				s.setPair(lead, b1)
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
// selects whether escapes are read; when false, or when data starts with no
// escape, the character is the literal UTF-8 rune. tokenMore means data ends
// inside what may be a longer spelling and final is not set.
func readToken(data []byte, escaped, final bool) (rune, int, spelling, int) {
	if escaped {
		var r rune
		var w int
		var sp spelling
		var more bool
		switch data[0] {
		case '%':
			r, w, sp, more = readPercent(data)
		case '\\':
			r, w, sp, more = readBackslash(data)
		case '&':
			r, w, sp, more = readReference(data)
		}
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
			return r, 3 * need, spelling{formPercent, hexCase}, false
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
	return r, 3, spelling{formPercent, c}, false
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
					return 0x10000 + (r-0xD800)<<10 + rune(low-0xDC00), 12, spelling{formJSONU, c}, false
				}
			}
		}
		return r, 6, spelling{formJSONU, c}, false
	case 'x':
		value, c, ok, more := readHex(data[2:], 2)
		if !ok {
			return 0, 0, spelling{}, more
		}
		return rune(value), 4, spelling{formHexEscape, c}, false
	}
	if r, ok := jsonShort[data[1]]; ok {
		return r, 2, spelling{formJSONShort, 0}, false
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
				return r, i + 1, spelling{formHTMLNamed, 0}, false
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
			return rune(value), i + 1, spelling{f, hexCase}, false
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
				if n.fold && r != want {
					sp.hexCase = 'A'
				} else if n.fold && unicode.IsLetter(r) {
					sp.hexCase = 'a'
				}
				spellings = append(spellings, sp)
				at += w
				break
			}
			// The literal reading is tried byte by byte when an escape does
			// not spell the wanted character.
			if escaped && w > 1 && sp.form != formLiteral {
				lr, lw, lsp, _ := readToken(data[at:], false, true)
				if equalRune(lr, want, n.fold) {
					spellings = append(spellings, lsp)
					at += lw
					break
				}
			}
			if k == 0 || gap >= maxGap || !isGap(r) {
				return 0, spellings, matchNone
			}
			at += w
		}
	}
	return at, spellings, matchFound
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
		dst = spell(dst, r, sp.form, hexCase)
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
// n*maxToken + (n-1)*maxGap*maxToken bytes, which bounds held: 9,600 bytes
// for a 48-character secret.
func (s *scrubber) scan(dst, data []byte, final bool) (out []byte, held int) {
	out = dst
	emitted := 0
	var spellings, best []spelling
	for i := 0; i < len(data); i++ {
		for i < len(data) && !s.mayStart(data, i) {
			i++
		}
		if i == len(data) {
			break
		}
		bestEnd, bestNeedle, more := -1, -1, false
		// Where an escape starts, both readings are tried: the escape, and
		// the literal byte for a needle that itself holds that byte.
		passes := 1
		if isEscapeStart(data[i]) {
			passes = 2
		}
		for pass := 0; pass < passes; pass++ {
			escaped := pass == 0
			r, w, st := rune(data[i]), 1, tokenOK
			if r >= utf8.RuneSelf || isEscapeStart(data[i]) {
				r, w, _, st = readToken(data[i:], escaped, final)
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
				if (!escaped && !n.literalEscape) || (next != 0 && len(n.runes) > 1 && !equalRune(rune(next), n.runes[1], n.fold)) {
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
			out = append(out, data[emitted:i]...)
			return out, len(data) - i
		}
		if bestNeedle < 0 {
			continue
		}
		out = append(out, data[emitted:i]...)
		out = encodeRepl(out, &s.needles[bestNeedle], best)
		emitted = bestEnd
		i = bestEnd - 1
	}
	return append(out, data[emitted:]...), 0
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

	if len(state.canonical) > 0 && refuseCredentialHeaderNames(resp.Header, scrub, state.values) {
		return refuseResponse(tctx, req, names, "response_header_name", "response header name cannot be checked for a held secret\n"), nil
	}

	scrubHeaders(resp.Header, scrub)

	if req.Method == http.MethodHead || resp.ContentLength == 0 ||
		resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	// Bytes the proxy cannot read as text cannot be scrubbed. The request had
	// its Accept-Encoding removed, so net/http decodes gzip itself; any other
	// encoding is a host that compresses unasked.
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return refuseResponse(tctx, req, names, "response_encoding", "response encoding cannot be checked for a held secret\n"), nil
	}

	// Read the upstream stream directly: the buffered body would hold the
	// whole response in memory first.
	body := transform.RequireBufferedBody(resp.Body)
	stream := body.StreamingReader()
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
