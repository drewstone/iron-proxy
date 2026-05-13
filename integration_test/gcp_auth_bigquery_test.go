package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGCPAuthBigQuery boots the proxy with the gcp_auth transform configured
// to mint OAuth2 access tokens from the service account JSON in
// GCP_BIGQUERY_SERVICE_ACCOUNT_KEY, then runs a BigQuery query through the
// proxy and asserts the first cell of the first row is returned. The client
// sends no Authorization header — the proxy injects one after minting a token
// from the keyfile.
//
// Requires a BigQuery table at test_dataset.test_table with a test_field
// column readable by the configured service account.
func TestGCPAuthBigQuery(t *testing.T) {
	keyJSON := os.Getenv("GCP_BIGQUERY_SERVICE_ACCOUNT_KEY")
	if keyJSON == "" {
		t.Skip("GCP_BIGQUERY_SERVICE_ACCOUNT_KEY not set")
	}

	var meta struct {
		ProjectID string `json:"project_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(keyJSON), &meta))
	require.NotEmpty(t, meta.ProjectID, "service account JSON missing project_id")

	tmpDir := t.TempDir()
	binary := proxyBinary(t)
	cfgPath := renderConfig(t, tmpDir, "gcp_auth_bigquery.yaml", nil)

	proxy := startProxy(t, binary, cfgPath, []string{
		"GCP_BIGQUERY_SERVICE_ACCOUNT_KEY=" + keyJSON,
	})

	// Trust the proxy's CA so the client accepts the MITM cert it presents
	// for bigquery.googleapis.com.
	caPath := filepath.Join(repoRoot(t), "tmp", "ca.crt")
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err, "expected proxy CA at %s — generate it with: ./iron-proxy generate-ca -outdir tmp -alg ed25519", caPath)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	proxyURL, err := url.Parse("http://" + proxy.HTTPAddr)
	require.NoError(t, err)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	queryBody, err := json.Marshal(map[string]any{
		"query":        "SELECT test_field FROM test_dataset.test_table LIMIT 1",
		"useLegacySql": false,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := "https://bigquery.googleapis.com/bigquery/v2/projects/" + meta.ProjectID + "/queries"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(queryBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "BigQuery response: %s", string(body))

	var qr struct {
		JobComplete bool `json:"jobComplete"`
		Rows        []struct {
			F []struct {
				V any `json:"v"`
			} `json:"f"`
		} `json:"rows"`
	}
	require.NoError(t, json.Unmarshal(body, &qr))
	require.True(t, qr.JobComplete, "BigQuery job not complete in synchronous response: %s", string(body))
	require.NotEmpty(t, qr.Rows, "no rows returned from test_dataset.test_table")
	require.NotEmpty(t, qr.Rows[0].F, "first row has no fields")
	require.NotNil(t, qr.Rows[0].F[0].V, "first cell of first row is nil")

	t.Logf("test_dataset.test_table.test_field first value: %v", qr.Rows[0].F[0].V)
}
