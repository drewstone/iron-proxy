package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ironsh/iron-proxy/internal/transform"
	"golang.org/x/net/http/httpguts"
)

// Presentation is the unchanged AgentProfile.proxySecrets component selector.
type presentationConfig struct {
	Type     string `yaml:"type"`
	Name     string `yaml:"name,omitempty"`
	Username string `yaml:"username,omitempty"`
}

var canonicalPath = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()+,=:@/-]*$`)
var canonicalHost = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validCanonicalPath(value string) bool {
	if !canonicalPath.MatchString(value) || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func canonicalConfig(entry *secretEntry) (*replaceConfig, error) {
	p := entry.Presentation
	if p == nil || entry.ProxyValue == "" || entry.ExpiresAt.IsZero() || entry.Replace != nil || entry.Inject != nil || len(entry.MatchHeaders) > 0 || entry.MatchBody || len(entry.Rules) == 0 {
		return nil, fmt.Errorf("canonical secret requires presentation, placeholder, expiry and exact host rules")
	}
	switch p.Type {
	case "bearer":
		if p.Name != "" || p.Username != "" {
			return nil, fmt.Errorf("invalid bearer presentation")
		}
	case "basic":
		if p.Name != "" || p.Username == "" {
			return nil, fmt.Errorf("invalid basic presentation")
		}
		for _, c := range p.Username {
			if c < 33 || c > 126 || c == ':' {
				return nil, fmt.Errorf("invalid basic username")
			}
		}
	case "header":
		if p.Username != "" || !httpguts.ValidHeaderFieldName(p.Name) {
			return nil, fmt.Errorf("invalid header presentation")
		}
		switch strings.ToLower(p.Name) {
		case "authorization", "proxy-authorization", "proxy-authenticate", "host", "connection", "keep-alive", "proxy-connection", "content-length", "transfer-encoding", "trailer", "upgrade", "te":
			return nil, fmt.Errorf("routing headers cannot carry secrets")
		}
	case "query":
		if p.Username != "" || p.Name == "" || !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).MatchString(p.Name) {
			return nil, fmt.Errorf("invalid query presentation")
		}
	default:
		return nil, fmt.Errorf("unsupported canonical presentation")
	}
	for _, rule := range entry.Rules {
		if !canonicalHost.MatchString(rule.Host) || rule.CIDR != "" || (rule.Methods != nil && len(rule.Methods) == 0) || (rule.Paths != nil && len(rule.Paths) == 0) {
			return nil, fmt.Errorf("canonical secret requires an exact FQDN")
		}
		for _, method := range rule.Methods {
			if !regexp.MustCompile(`^[A-Z]+$`).MatchString(method) {
				return nil, fmt.Errorf("invalid canonical method")
			}
		}
		for _, path := range rule.Paths {
			if !validCanonicalPath(strings.TrimSuffix(path, "*")) || (strings.Contains(path, "*") && !strings.HasSuffix(path, "/*")) {
				return nil, fmt.Errorf("invalid canonical path")
			}
		}
	}
	return &replaceConfig{ProxyValue: entry.ProxyValue, Presentation: p, ExpiresAt: entry.ExpiresAt, TLSOnly: true, ScrubResponse: true, Require: entry.Require}, nil
}

func authority(value string) (string, string, bool) {
	host, port := value, "443"
	if strings.Contains(value, ":") {
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return "", "", false
		}
	}
	for _, c := range host {
		if c > 127 {
			return "", "", false
		}
	}
	n, err := strconv.Atoi(port)
	return strings.ToLower(host), strconv.Itoa(n), err == nil && n > 0 && n <= 65535 && canonicalHost.MatchString(strings.ToLower(host))
}

func (sec *resolvedSecret) canonicalScope(tctx *transform.TransformContext, req *http.Request) bool {
	host, port, ok := authority(req.Host)
	sni, _, validSNI := authority(tctx.SNI)
	if !ok || req.TLS == nil || !validSNI || sni != host {
		return false
	}
	if req.URL.Host != "" {
		h, p, valid := authority(req.URL.Host)
		if !valid || h != host || p != port || req.URL.Scheme != "https" {
			return false
		}
	}
	if tctx.Tunnel != nil {
		h, p, valid := authority(tctx.Tunnel.Target)
		if !valid || h != host || p != port {
			return false
		}
	}
	return sec.permits(req, host)
}

func (sec *resolvedSecret) permits(req *http.Request, host string) bool {
	if !validCanonicalPath(req.URL.Path) || strings.Contains(req.URL.EscapedPath(), "%") {
		return false
	}
	for _, rule := range sec.rules {
		if !rule.MatchesHost(host) || (rule.Methods != nil && !rule.Methods[req.Method]) {
			continue
		}
		if rule.Paths == nil {
			return true
		}
		for _, path := range rule.Paths {
			if path == req.URL.Path || (strings.HasSuffix(path, "/*") && strings.HasPrefix(req.URL.Path, strings.TrimSuffix(path, "*"))) {
				return true
			}
		}
	}
	return false
}

// Select a complete component before resolving any source. Unrelated public requests pass.
func (sec *resolvedSecret) component(req *http.Request) (func(string), string, error) {
	p, placeholder := sec.presentation, sec.proxyValue
	if p.Type == "query" {
		parts := strings.Split(req.URL.RawQuery, "&")
		selected := -1
		for i, part := range parts {
			rawName, rawValue, _ := strings.Cut(part, "=")
			name, err := url.QueryUnescape(rawName)
			if err != nil || !utf8.ValidString(name) {
				return nil, "", fmt.Errorf("malformed query selector")
			}
			if name != p.Name {
				continue
			}
			if selected >= 0 {
				return nil, "", fmt.Errorf("duplicate selected query")
			}
			selected = i
			value, err := url.QueryUnescape(rawValue)
			if err != nil || !utf8.ValidString(value) {
				return nil, "", fmt.Errorf("malformed selected query")
			}
		}
		if selected < 0 {
			return nil, "", nil
		}
		name, raw, _ := strings.Cut(parts[selected], "=")
		value, _ := url.QueryUnescape(raw)
		if value != placeholder {
			if strings.Contains(value, placeholder) {
				return nil, "", fmt.Errorf("embedded placeholder")
			}
			return nil, "", nil
		}
		return func(real string) {
			parts[selected] = name + "=" + url.QueryEscape(real)
			req.URL.RawQuery = strings.Join(parts, "&")
		}, "query:" + p.Name, nil
	}
	name := "Authorization"
	if p.Type == "header" {
		name = p.Name
	}
	var values []string
	for key, entries := range req.Header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	if len(values) == 0 {
		return nil, "", nil
	}
	if len(values) != 1 {
		return nil, "", fmt.Errorf("duplicate selected header")
	}
	value, expected := values[0], placeholder
	format := func(real string) string { return real }
	switch p.Type {
	case "bearer":
		expected = "Bearer " + placeholder
		format = func(real string) string { return "Bearer " + real }
	case "basic":
		if !strings.HasPrefix(value, "Basic ") {
			return nil, "", nil
		}
		encoded := strings.TrimPrefix(value, "Basic ")
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || !utf8.Valid(decoded) {
			return nil, "", fmt.Errorf("malformed basic credential")
		}
		if string(decoded) != p.Username+":"+placeholder {
			if strings.Contains(string(decoded), placeholder) {
				return nil, "", fmt.Errorf("embedded basic placeholder")
			}
			return nil, "", nil
		}
		expected = value
		format = func(real string) string {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(p.Username+":"+real))
		}
	}
	if value != expected {
		if strings.Contains(value, placeholder) {
			return nil, "", fmt.Errorf("embedded placeholder")
		}
		return nil, "", nil
	}
	return func(real string) {
		for key := range req.Header {
			if strings.EqualFold(key, name) {
				delete(req.Header, key)
			}
		}
		req.Header.Set(name, format(real))
	}, "header:" + name, nil
}

func (sec *resolvedSecret) swapCanonical(ctx context.Context, tctx *transform.TransformContext, req *http.Request) ([]string, error) {
	if tctx.TunnelAdmission {
		return nil, nil
	}
	apply, location, err := sec.component(req)
	if err != nil || apply == nil {
		return nil, err
	}
	if !sec.canonicalScope(tctx, req) || !time.Now().Before(sec.expiresAt) {
		return nil, fmt.Errorf("canonical secret scope or expiry refused")
	}
	value, err := sec.source.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("canonical secret unavailable")
	}
	if !time.Now().Before(sec.expiresAt) || ((sec.presentation.Type == "header" || sec.presentation.Type == "bearer") && !httpguts.ValidHeaderFieldValue(value)) {
		return nil, fmt.Errorf("canonical secret expired or invalid")
	}
	apply(value)
	rememberScrub(req, sec, value)
	return []string{location}, nil
}

// Reverse mappings are private to this request; aliases and rotations cannot reselect a value.
type scrubContextKey struct{}
type requestScrubs struct {
	canonical []*resolvedSecret
	authority string
	pairs     []scrubPair
	names     []string
	// values holds each canonical source value, used only to refuse a response
	// header name that reflects one in the case-insensitive HTTP namespace.
	values []string
}

// refuseCredentialHeaderNames reports a protected response whose header name
// reflects a captured value. Go canonicalizes a response field name (the first
// letter and each letter after a dash) before the case-sensitive value scrub
// runs, so a lowercase credential used as a field name would otherwise pass;
// names are matched case-insensitively here, while body and value matching
// stays case sensitive. A name whose projection would collide with another
// header's name, compared case-insensitively as HTTP names are and as the
// forwarded header merges them, is refused too.
func refuseCredentialHeaderNames(header http.Header, scrub *scrubber, values []string) bool {
	projected := make(map[string]bool, len(header))
	for name := range header {
		lower := strings.ToLower(name)
		for _, value := range values {
			if len(value) >= minFragment && strings.Contains(lower, strings.ToLower(value)) {
				return true
			}
		}
		key := strings.ToLower(scrub.text(name))
		if projected[key] {
			return true
		}
		projected[key] = true
	}
	return false
}

func rememberScrub(req *http.Request, sec *resolvedSecret, value string) {
	if !sec.scrubResponse || sec.mode != "replace" {
		return
	}
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	if state == nil {
		state = &requestScrubs{}
		*req = *req.WithContext(context.WithValue(req.Context(), scrubContextKey{}, state))
	}
	pairs := scrubPairsFor(value, sec.proxyValue)
	if sec.presentation != nil && sec.presentation.Type == "basic" {
		encode := func(secret string) []byte {
			return []byte(base64.StdEncoding.EncodeToString([]byte(sec.presentation.Username + ":" + secret)))
		}
		pairs = append([]scrubPair{{needle: encode(value), repl: encode(sec.proxyValue)}}, pairs...)
	}
	if sec.presentation != nil {
		state.canonical = append(state.canonical, sec)
		state.authority = req.Host
		state.pairs = append(pairs, state.pairs...)
		state.values = append(state.values, value)
	} else {
		state.pairs = append(state.pairs, pairs...)
	}
	state.names = append(state.names, sec.source.Name())
	req.Header.Del("Accept-Encoding")
}

// Recheck the actual destination after routing and on every send, including retries.
// Request transforms can redeem a grant only for the original HTTPS authority.
func ValidateFinalDestination(req *http.Request) error {
	state, _ := req.Context().Value(scrubContextKey{}).(*requestScrubs)
	if state == nil || len(state.canonical) == 0 {
		return nil
	}
	host, port, ok := authority(req.URL.Host)
	originalHost, originalPort, originalOK := authority(state.authority)
	valid := ok && originalOK && host == originalHost && port == originalPort && (req.URL.Scheme == "https" || req.URL.Scheme == "wss") && req.URL.User == nil
	if req.Host != "" {
		h, p, validHost := authority(req.Host)
		valid = valid && validHost && h == host && p == port
	}
	for _, sec := range state.canonical {
		if !valid || !time.Now().Before(sec.expiresAt) || !sec.permits(req, host) {
			return fmt.Errorf("canonical secret destination refused")
		}
	}
	return nil
}
