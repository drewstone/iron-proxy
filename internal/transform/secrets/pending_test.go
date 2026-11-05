package secrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const pendingToken = "proxy-model-token-SALT"

func resetPendingSlots(t *testing.T) {
	t.Helper()
	pendingSlots.Lock()
	pendingSlots.byValue = map[string]*pendingSlot{}
	pendingSlots.Unlock()
}

func pendingConfig(wait string) secretsConfig {
	return secretsConfig{
		Pending: []pendingEntry{{
			ProxyValue:   pendingToken,
			MatchHeaders: []string{"Authorization"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
			Name:         "OPENCODE_MODEL_API_KEY",
			SandboxID:    "sb-1",
		}},
		PendingWait: wait,
	}
}

func installedConfig() secretsConfig {
	return secretsConfig{Secrets: []secretEntry{defaultEntry(func(e *secretEntry) {
		e.ProxyValue = pendingToken
	})}}
}

func pendingReq() *http.Request {
	req := openaiReq("POST", "/v1/chat")
	req.Header.Set("Authorization", "Bearer "+pendingToken)
	return req
}

func TestPending_HeldRequestIsSwappedWhenTheInstallArrives(t *testing.T) {
	resetPendingSlots(t)
	old, err := newFromConfig(pendingConfig("5s"), testRegistry())
	require.NoError(t, err)

	req := pendingReq()
	type outcome struct {
		res *transform.TransformResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := old.TransformRequest(context.Background(), &transform.TransformContext{}, req)
		done <- outcome{res, err}
	}()

	select {
	case <-done:
		t.Fatal("request was not held while the placeholder was pending")
	case <-time.After(100 * time.Millisecond):
	}

	// The reload builds the next pipeline's transform, which carries the secret.
	_, err = newFromConfig(installedConfig(), testRegistry())
	require.NoError(t, err)

	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.Equal(t, transform.ActionContinue, got.res.Action)
		require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	case <-time.After(2 * time.Second):
		t.Fatal("held request was not released by the install")
	}
}

func TestPending_TimeoutFailsClosedWithoutSendingThePlaceholder(t *testing.T) {
	resetPendingSlots(t)
	s, err := newFromConfig(pendingConfig("50ms"), testRegistry())
	require.NoError(t, err)

	req := pendingReq()
	start := time.Now()
	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusServiceUnavailable, res.Response.StatusCode)
	body, _ := io.ReadAll(res.Response.Body)
	require.Contains(t, string(body), "OPENCODE_MODEL_API_KEY")
	require.Contains(t, string(body), "not sent upstream")
}

func TestPending_RequestsThatDoNotCarryThePlaceholderAreNotHeld(t *testing.T) {
	resetPendingSlots(t)
	s, err := newFromConfig(pendingConfig("5s"), testRegistry())
	require.NoError(t, err)

	other := openaiReq("GET", "/v1/models")
	other.Header.Set("Authorization", "Bearer sk-user-own-key")
	start := time.Now()
	doTransform(t, s, other)
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, "Bearer sk-user-own-key", other.Header.Get("Authorization"))

	elsewhere := httptest.NewRequest("POST", "http://example.com/x", nil)
	elsewhere.Host = "example.com"
	elsewhere.Header.Set("Authorization", "Bearer "+pendingToken)
	start = time.Now()
	doTransform(t, s, elsewhere)
	require.Less(t, time.Since(start), time.Second)
}

func TestPending_AlreadyInstalledSwapsWithoutWaiting(t *testing.T) {
	resetPendingSlots(t)
	// The old pipeline still holds its pending entry for requests already inside it.
	old, err := newFromConfig(pendingConfig("5s"), testRegistry())
	require.NoError(t, err)
	_, err = newFromConfig(installedConfig(), testRegistry())
	require.NoError(t, err)

	req := pendingReq()
	start := time.Now()
	doTransform(t, old, req)
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestPending_RedeclaredPlaceholderWaitsAgain(t *testing.T) {
	resetPendingSlots(t)
	_, err := newFromConfig(pendingConfig("5s"), testRegistry())
	require.NoError(t, err)
	_, err = newFromConfig(installedConfig(), testRegistry())
	require.NoError(t, err)
	again, err := newFromConfig(pendingConfig("50ms"), testRegistry())
	require.NoError(t, err)
	res, err := again.TransformRequest(context.Background(), &transform.TransformContext{}, pendingReq())
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestPending_CancelledRequestFailsClosed(t *testing.T) {
	resetPendingSlots(t)
	s, err := newFromConfig(pendingConfig("5s"), testRegistry())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	var res *transform.TransformResult
	go func() {
		defer wg.Done()
		res, _ = s.TransformRequest(ctx, &transform.TransformContext{}, pendingReq())
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestPending_RejectsBadWait(t *testing.T) {
	resetPendingSlots(t)
	_, err := newFromConfig(pendingConfig("soon"), testRegistry())
	require.Error(t, err)
}
