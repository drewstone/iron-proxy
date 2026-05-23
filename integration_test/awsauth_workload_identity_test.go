package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"
)

// TestAWSAuthWorkloadIdentity boots the proxy with the aws_auth transform
// configured via credentials_provider: workload_identity. The proxy's env
// carries AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, which
// the AWS SDK default credential chain resolves at first Retrieve. This
// exercises the full workload_identity → lazyDefaultChainProvider →
// awsconfig.LoadDefaultConfig path without requiring real IRSA / IMDS infra,
// and confirms that a session token flows through to the outbound request.
func TestAWSAuthWorkloadIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	var (
		mu      sync.Mutex
		gotAuth string
		gotDate string
		gotTok  string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		gotTok = r.Header.Get("X-Amz-Security-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "awsauth_workload_identity.yaml", nil)
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SESSION_TOKEN=test-workload-session-token",
		// Skip the default-region IMDS lookup in CI: the AWS SDK only reads
		// region from env (not creds), and the signer takes its region from
		// the inbound credential scope, but LoadDefaultConfig probes IMDS for
		// region metadata otherwise.
		"AWS_REGION=us-east-1",
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	body := []byte(`{"prompt":"hi"}`)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/model/foo/invoke", proxy.HTTPAddr), strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	// Pre-sign with placeholder credentials, as a sandboxed AWS SDK would. The
	// proxy is expected to strip this signature and re-sign with the real env
	// credentials it resolved through the workload_identity provider.
	placeholder := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	sum := sha256.Sum256(body)
	require.NoError(t, v4.NewSigner().SignHTTP(
		context.Background(), placeholder, req, hex.EncodeToString(sum[:]),
		"bedrock", "us-east-1", time.Now().UTC(),
	))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 "), "Authorization = %q", gotAuth)
	require.Contains(t, gotAuth, "Credential=AKIAEXAMPLE/")
	require.NotContains(t, gotAuth, "AKIAIOSFODNN7EXAMPLE", "placeholder credential must not appear in outbound Authorization header")
	require.Contains(t, gotAuth, "/us-east-1/bedrock/aws4_request")
	require.Regexp(t, `^\d{8}T\d{6}Z$`, gotDate)
	require.Equal(t, "test-workload-session-token", gotTok, "session token from env must flow through workload_identity")
}
