package gcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

// tokenSourceBuilder turns a credentials_provider config node into a token
// source plus a best-effort principal identifier (email / unique id) for
// audit logging. Tests substitute a stub builder.
type tokenSourceBuilder func(ctx context.Context, node yaml.Node, scopes []string, logger *slog.Logger) (oauth2.TokenSource, string, error)

// providerTypeHint is used to peek at the type field before dispatching.
type providerTypeHint struct {
	Type string `yaml:"type"`
}

// BuildTokenSource dispatches a credentials_provider node through the default
// registry. Mirrors secrets.BuildSource. Refresh and caching are delegated to
// the returned oauth2.TokenSource (typically google.Credentials.TokenSource,
// which is internally cached).
func BuildTokenSource(ctx context.Context, node yaml.Node, scopes []string, logger *slog.Logger) (oauth2.TokenSource, string, error) {
	var hint providerTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, "", fmt.Errorf("parsing credentials_provider type: %w", err)
	}
	if hint.Type == "" {
		return nil, "", fmt.Errorf("credentials_provider.type is required")
	}
	registry := defaultTokenSourceRegistry()
	builder, ok := registry[hint.Type]
	if !ok {
		return nil, "", fmt.Errorf("unsupported credentials_provider type %q", hint.Type)
	}
	return builder(ctx, node, scopes, logger)
}

// defaultTokenSourceRegistry returns the standard token-source builders.
// Additional types (e.g. impersonated_service_account) are additive.
func defaultTokenSourceRegistry() map[string]tokenSourceBuilder {
	return map[string]tokenSourceBuilder{
		"workload_identity": buildWorkloadIdentity,
	}
}

// workloadIdentityConfig is the YAML shape for the workload_identity provider.
type workloadIdentityConfig struct {
	Type string `yaml:"type"`
}

// buildWorkloadIdentity defers to Google Application Default Credentials.
// This resolves GKE Workload Identity (via the metadata server), the
// GOOGLE_APPLICATION_CREDENTIALS keyfile, Workload Identity Federation
// external_account JSON, and gcloud user credentials, in that order.
func buildWorkloadIdentity(ctx context.Context, node yaml.Node, scopes []string, _ *slog.Logger) (oauth2.TokenSource, string, error) {
	var cfg workloadIdentityConfig
	if err := node.Decode(&cfg); err != nil {
		return nil, "", fmt.Errorf("parsing workload_identity provider: %w", err)
	}
	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, "", fmt.Errorf("loading GCP default credentials: %w", err)
	}
	if creds.TokenSource == nil {
		return nil, "", fmt.Errorf("GCP default credentials returned no token source")
	}
	principal := principalFromCredentialsJSON(creds.JSON)
	return creds.TokenSource, principal, nil
}

// principalFromCredentialsJSON extracts a human-readable identifier from a
// credentials JSON blob. Returns "" if no recognized field is present (e.g.
// metadata-server credentials carry no JSON).
func principalFromCredentialsJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var meta struct {
		ClientEmail                    string `json:"client_email"`
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ""
	}
	if meta.ClientEmail != "" {
		return meta.ClientEmail
	}
	return meta.ServiceAccountImpersonationURL
}
