// Package bodycapture implements a transform that captures request bodies of
// matching requests and exposes them via PipelineResult.BodyCapture for the
// audit emitters to render as top-level `request_body` and
// `request_body_truncated` audit fields.
//
// Phase 1a (litmus ENG-578): request bodies only. Response body capture is
// deferred to a follow-up — iron-proxy's BufferedBody is "buffer-then-replay"
// not "tee-stream", and buffering response bodies for matching hosts would
// stall SSE-streaming model replies (Anthropic / OpenAI) for the duration of
// the stream, breaking the candidate's terminal UX. Once iron-proxy gains
// tee-stream support, response capture can be added behind the same
// BodyCapture interface.
package bodycapture

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("body_capture", factory)
}

// defaultMaxRequestBodyBytes is the per-request cap when the config doesn't
// specify max_request_body_bytes. Sized for typical AI-prompt capture — a
// well-structured chat completion request is comfortably under 16 KB. Long
// conversation histories may truncate; the truncation flag in the audit
// surface lets downstream consumers see when this happens.
const defaultMaxRequestBodyBytes = 16 * 1024

// bodyCapture is the transform itself. Unexported because all external use
// goes through the factory registration.
type bodyCapture struct {
	rules               []hostmatch.Rule
	maxRequestBodyBytes int64
}

type config struct {
	MaxRequestBodyBytes int64                  `yaml:"max_request_body_bytes"`
	Rules               []hostmatch.RuleConfig `yaml:"rules"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing body_capture config: %w", err)
	}
	rules, err := hostmatch.CompileRules(c.Rules, "body_capture")
	if err != nil {
		return nil, err
	}
	maxBytes := c.MaxRequestBodyBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxRequestBodyBytes
	}
	return &bodyCapture{rules: rules, maxRequestBodyBytes: maxBytes}, nil
}

// Name returns the transform's registered name.
func (b *bodyCapture) Name() string { return "body_capture" }

// TransformRequest reads the request body via the pipeline's BufferedBody and,
// if the request matches a configured rule, attaches the captured (and
// possibly truncated) body bytes to TransformContext.BodyCapture. The proxy
// copies that onto PipelineResult after the pipeline returns; the audit
// emitters render it as top-level `request_body` + `request_body_truncated`.
//
// Always returns ActionContinue — body_capture is observation-only and never
// rejects a request. Read errors are annotated for observability and swallowed
// so a misbehaving body reader can't take down the request.
func (b *bodyCapture) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}
	if !hostmatch.MatchAnyRule(b.rules, req) {
		return cont, nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return cont, nil
	}
	bb := transform.RequireBufferedBody(req.Body)
	data, err := io.ReadAll(bb)
	if err != nil {
		tctx.Annotate("body_capture_error", err.Error())
		return cont, nil
	}
	if len(data) == 0 {
		return cont, nil
	}
	truncated := false
	if int64(len(data)) > b.maxRequestBodyBytes {
		data = data[:b.maxRequestBodyBytes]
		truncated = true
	}
	tctx.BodyCapture = &capture{
		requestBody:          string(data),
		requestBodyTruncated: truncated,
	}
	return cont, nil
}

// TransformResponse is a no-op for body_capture in Phase 1a. See the package
// doc for the rationale (tee-stream needed before response capture is safe).
func (b *bodyCapture) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// capture is the concrete implementation of transform.BodyCapture.
type capture struct {
	requestBody          string
	requestBodyTruncated bool
}

func (c *capture) RequestBody() string        { return c.requestBody }
func (c *capture) RequestBodyTruncated() bool { return c.requestBodyTruncated }
