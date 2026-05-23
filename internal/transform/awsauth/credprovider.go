package awsauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"gopkg.in/yaml.v3"
)

// credentialsProviderBuilder turns a credentials_provider config node into an
// aws.CredentialsProvider. Tests substitute a stub builder.
type credentialsProviderBuilder func(yaml.Node, *slog.Logger) (aws.CredentialsProvider, error)

// providerTypeHint is used to peek at the type field before dispatching.
type providerTypeHint struct {
	Type string `yaml:"type"`
}

// BuildCredentialsProvider dispatches a credentials_provider node through the
// default registry. Mirrors secrets.BuildSource. Returns an aws.CredentialsProvider
// suitable for handing directly to a SigV4 signer; refresh and caching are
// delegated to the AWS SDK.
func BuildCredentialsProvider(node yaml.Node, logger *slog.Logger) (aws.CredentialsProvider, error) {
	var hint providerTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing credentials_provider type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("credentials_provider.type is required")
	}
	registry := defaultCredentialsProviderRegistry()
	builder, ok := registry[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported credentials_provider type %q", hint.Type)
	}
	return builder(node, logger)
}

// defaultCredentialsProviderRegistry returns the standard provider builders.
// New types (assume_role, static, ...) are additive: register them here.
func defaultCredentialsProviderRegistry() map[string]credentialsProviderBuilder {
	return map[string]credentialsProviderBuilder{
		"workload_identity": buildWorkloadIdentity,
	}
}

// workloadIdentityConfig is the YAML shape for the workload_identity provider.
type workloadIdentityConfig struct {
	Type   string `yaml:"type"`
	Region string `yaml:"region,omitempty"`
}

// buildWorkloadIdentity returns a provider that defers to the AWS SDK default
// credential chain. The chain natively resolves IRSA, EKS Pod Identity, IMDSv2,
// environment variables, shared profiles, and SSO. Loading the SDK config is
// deferred to the first Retrieve so factory-time validation does not require a
// reachable metadata server. The result is wrapped in aws.CredentialsCache so
// refresh respects the provider's reported expiry.
func buildWorkloadIdentity(node yaml.Node, _ *slog.Logger) (aws.CredentialsProvider, error) {
	var cfg workloadIdentityConfig
	if err := node.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing workload_identity provider: %w", err)
	}
	return aws.NewCredentialsCache(&lazyDefaultChainProvider{region: cfg.Region}), nil
}

// lazyDefaultChainProvider loads the AWS default credential chain on first
// Retrieve and reuses the resulting provider thereafter. The inner provider
// (returned by awsconfig.LoadDefaultConfig) already handles its own expiry, so
// callers wrap this in aws.NewCredentialsCache rather than caching here.
type lazyDefaultChainProvider struct {
	region string

	mu    sync.Mutex
	inner aws.CredentialsProvider
}

func (p *lazyDefaultChainProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	inner := p.inner
	p.mu.Unlock()
	if inner == nil {
		loaded, err := p.load(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}
		inner = loaded
	}
	return inner.Retrieve(ctx)
}

func (p *lazyDefaultChainProvider) load(ctx context.Context) (aws.CredentialsProvider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inner != nil {
		return p.inner, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if p.region != "" {
		opts = append(opts, awsconfig.WithRegion(p.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS default credential chain: %w", err)
	}
	if cfg.Credentials == nil {
		return nil, fmt.Errorf("AWS default credential chain returned no credentials provider")
	}
	p.inner = cfg.Credentials
	return p.inner, nil
}
