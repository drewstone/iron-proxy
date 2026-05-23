package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGCPAuthWorkloadIdentity boots the proxy with gcp_auth configured via
// credentials_provider: workload_identity. ADC is steered to a generated
// service-account JSON keyfile via GOOGLE_APPLICATION_CREDENTIALS, with its
// token_uri pointing at a local httptest server that mints a fake bearer.
// This exercises the full workload_identity → google.FindDefaultCredentials →
// TokenSource path without requiring GKE Workload Identity or a real GCP
// metadata server, and confirms the minted bearer reaches the upstream.
func TestGCPAuthWorkloadIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	const wantToken = "workload-identity-bearer"
	var tokenCalls atomic.Int64
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": wantToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	var (
		mu      sync.Mutex
		gotAuth string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	keyfile := writeWorkloadIdentityKeyfile(t, tmpDir, tokenSrv.URL)

	cfgPath := renderConfig(t, tmpDir, "gcp_auth_workload_identity.yaml", nil)
	env := []string{
		"GOOGLE_APPLICATION_CREDENTIALS=" + keyfile,
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/v1/projects", proxy.HTTPAddr), nil)
	require.NoError(t, err)
	req.Host = upstreamHost
	// The agent SDK would have a placeholder bearer of its own. gcp_auth
	// overwrites Authorization unconditionally, so the placeholder is not
	// load-bearing for the assertion; we set one anyway to mirror the agent
	// flow and confirm it is replaced.
	req.Header.Set("Authorization", "Bearer agent-placeholder")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "Bearer "+wantToken, gotAuth, "minted workload-identity bearer must reach upstream")
	require.NotContains(t, gotAuth, "agent-placeholder", "agent placeholder bearer must be replaced")
	require.Equal(t, int64(1), tokenCalls.Load(), "token endpoint should be hit exactly once and then cached")
}

// writeWorkloadIdentityKeyfile generates a service-account JSON keyfile with a
// freshly minted RSA key and a tokenURI pointing at the test's fake token
// server. google.FindDefaultCredentials accepts this via the
// GOOGLE_APPLICATION_CREDENTIALS env leg of the ADC chain.
func writeWorkloadIdentityKeyfile(t *testing.T, dir, tokenURI string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	keyfile := map[string]string{
		"type":         "service_account",
		"project_id":   "iron-proxy-workload-identity-test",
		"private_key":  string(pemBytes),
		"client_email": "workload-identity@iron-proxy-test.iam.gserviceaccount.com",
		"token_uri":    tokenURI,
	}
	data, err := json.MarshalIndent(keyfile, "", "  ")
	require.NoError(t, err)

	path := filepath.Join(dir, "workload-identity-sa.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

