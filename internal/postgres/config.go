// Package postgres implements an iron-proxy listener that MITM-proxies
// PostgreSQL traffic so a static role policy is in effect on every query the
// upstream database sees.
//
// The listener accepts client connections, authenticates them against
// proxy-managed credentials, opens its own authenticated connection upstream
// (handling SCRAM/MD5 termination via pgconn), issues a single
// `SET ROLE "<role>"` on the upstream session, then relays the PostgreSQL
// wire protocol bidirectionally.
//
// Deployment assumption: if PgBouncer (or any pooler) sits between the proxy
// and PostgreSQL, it must be configured in session-pool mode. Transaction or
// statement pooling silently rebinds backends between queries and would
// nullify the role injection. This is not probed at runtime — the constraint
// is enforced by deployment configuration.
//
// While the relay is running the proxy is mostly transparent: it rejects only
// client-issued role-changing statements (`SET ROLE`, `RESET ROLE`,
// `SET SESSION AUTHORIZATION`, `RESET SESSION AUTHORIZATION`), the function-
// call equivalents (`set_config('role', ...)`), DO blocks, and multi-statement
// Simple Queries. Extended Query, COPY, and prepared statements pass through
// unchanged.
//
// Multiple servers are supported: the top-level postgres: key is a list, so
// one proxy process can front several databases (each with its own listen
// address, upstream, client credentials, and injected role).
package postgres

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Upstream SSL modes accepted by the proxy→database connection.
const (
	UpstreamSSLDisable = "disable"
	UpstreamSSLRequire = "require"
)

// ServerConfig is one entry in the top-level postgres: list — a single
// listener fronting a single upstream database.
type ServerConfig struct {
	// Name identifies the server in logs and error messages. Required and
	// must be unique across all postgres servers in the config.
	Name string `yaml:"name"`

	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	// Must be unique across all postgres servers.
	Listen string `yaml:"listen"`

	// Upstream is the database the proxy connects to on behalf of clients.
	Upstream UpstreamConfig `yaml:"upstream"`

	// Client describes the credentials clients must present when authenticating
	// to the proxy. The proxy verifies a single shared user/password pair —
	// per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

	// Role is the Postgres role the proxy SETs at session start. Every query
	// the client subsequently issues runs as this role on the upstream database.
	Role string `yaml:"role"`
}

// UpstreamConfig describes the database the proxy forwards to.
type UpstreamConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	SSLMode     string `yaml:"sslmode"`
	UserEnv     string `yaml:"user_env"`
	PasswordEnv string `yaml:"password_env"`
	Database    string `yaml:"database"`
}

// ClientConfig describes the credentials the proxy demands from clients.
type ClientConfig struct {
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
}

// Policy is the compiled, runtime form of a single ServerConfig.
type Policy struct {
	name   string
	listen string
	role   string

	upstreamHost     string
	upstreamPort     int
	upstreamSSLMode  string
	upstreamUser     string
	upstreamPassword string
	upstreamDB       string

	clientUser     string
	clientPassword string
}

// Name returns the server's configured name.
func (p *Policy) Name() string { return p.name }

// Listen returns the bind address.
func (p *Policy) Listen() string { return p.listen }

// Role returns the role the proxy SETs upstream at session start.
func (p *Policy) Role() string { return p.role }

// UpstreamHost returns the upstream database host.
func (p *Policy) UpstreamHost() string { return p.upstreamHost }

// UpstreamPort returns the upstream database port.
func (p *Policy) UpstreamPort() int { return p.upstreamPort }

// UpstreamSSLMode returns the upstream sslmode (disable|require).
func (p *Policy) UpstreamSSLMode() string { return p.upstreamSSLMode }

// UpstreamUser returns the username the proxy uses to authenticate upstream.
func (p *Policy) UpstreamUser() string { return p.upstreamUser }

// UpstreamPassword returns the password the proxy uses to authenticate
// upstream. It is loaded from the env var named in UpstreamConfig.PasswordEnv.
func (p *Policy) UpstreamPassword() string { return p.upstreamPassword }

// UpstreamDatabase returns the dbname the proxy connects to upstream.
func (p *Policy) UpstreamDatabase() string { return p.upstreamDB }

// VerifyClient returns whether the given (user, password) pair matches the
// configured client credentials.
func (p *Policy) VerifyClient(user, password string) bool {
	return user == p.clientUser && password == p.clientPassword
}

// ClientUser returns the user clients must present to the proxy.
func (p *Policy) ClientUser() string { return p.clientUser }

// LoadFromNode decodes a raw yaml.Node into a list of ServerConfigs and
// compiles each into a Policy. An empty node (the postgres: key absent from
// the source document) returns (nil, nil) so callers can treat "no postgres
// listeners" as a normal case. An empty list (`postgres: []`) returns the
// same.
func LoadFromNode(node yaml.Node) ([]*Policy, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var servers []ServerConfig
	if err := node.Decode(&servers); err != nil {
		return nil, fmt.Errorf("decoding postgres config: %w", err)
	}
	return Compile(servers)
}

// Compile validates and compiles ServerConfigs into Policies. Returns
// (nil, nil) when the input list is empty so callers can treat "not
// configured" as a no-op without a sentinel error.
func Compile(servers []ServerConfig) ([]*Policy, error) {
	if len(servers) == 0 {
		return nil, nil
	}

	seenNames := make(map[string]bool, len(servers))
	policies := make([]*Policy, 0, len(servers))

	for i, s := range servers {
		p, err := compileOne(s, i)
		if err != nil {
			return nil, err
		}
		if seenNames[p.name] {
			return nil, fmt.Errorf("postgres[%d]: duplicate server name %q", i, p.name)
		}
		seenNames[p.name] = true
		policies = append(policies, p)
	}

	// We deliberately don't validate listen-address uniqueness here: ":0"
	// asks the OS to assign an ephemeral port, so two ":0" entries are
	// legitimate (and used by tests). Real conflicts surface as a clean
	// "address already in use" from net.Listen at startup.

	return policies, nil
}

func compileOne(c ServerConfig, idx int) (*Policy, error) {
	ctx := fmt.Sprintf("postgres[%d]", idx)
	if c.Name != "" {
		ctx = fmt.Sprintf("postgres[%q]", c.Name)
	}

	if c.Name == "" {
		return nil, fmt.Errorf("%s: name is required", ctx)
	}
	if c.Listen == "" {
		return nil, fmt.Errorf("%s: listen is required", ctx)
	}
	if c.Role == "" {
		return nil, fmt.Errorf("%s: role is required", ctx)
	}
	if c.Upstream.Host == "" {
		return nil, fmt.Errorf("%s: upstream.host is required", ctx)
	}
	if c.Upstream.Port == 0 {
		c.Upstream.Port = 5432
	}
	if c.Upstream.Database == "" {
		return nil, fmt.Errorf("%s: upstream.database is required", ctx)
	}
	if c.Upstream.UserEnv == "" {
		return nil, fmt.Errorf("%s: upstream.user_env is required", ctx)
	}
	if c.Upstream.PasswordEnv == "" {
		return nil, fmt.Errorf("%s: upstream.password_env is required", ctx)
	}
	if c.Upstream.SSLMode == "" {
		c.Upstream.SSLMode = UpstreamSSLDisable
	}
	switch c.Upstream.SSLMode {
	case UpstreamSSLDisable, UpstreamSSLRequire:
	default:
		return nil, fmt.Errorf("%s: upstream.sslmode must be %q or %q; got %q", ctx, UpstreamSSLDisable, UpstreamSSLRequire, c.Upstream.SSLMode)
	}
	if c.Client.User == "" {
		return nil, fmt.Errorf("%s: client.user is required", ctx)
	}
	if c.Client.PasswordEnv == "" {
		return nil, fmt.Errorf("%s: client.password_env is required", ctx)
	}

	upstreamUser := os.Getenv(c.Upstream.UserEnv)
	if upstreamUser == "" {
		return nil, fmt.Errorf("%s: upstream.user_env %q is not set in the environment", ctx, c.Upstream.UserEnv)
	}
	upstreamPassword := os.Getenv(c.Upstream.PasswordEnv)
	if upstreamPassword == "" {
		return nil, fmt.Errorf("%s: upstream.password_env %q is not set in the environment", ctx, c.Upstream.PasswordEnv)
	}
	clientPassword := os.Getenv(c.Client.PasswordEnv)
	if clientPassword == "" {
		return nil, fmt.Errorf("%s: client.password_env %q is not set in the environment", ctx, c.Client.PasswordEnv)
	}

	return &Policy{
		name:             c.Name,
		listen:           c.Listen,
		role:             c.Role,
		upstreamHost:     c.Upstream.Host,
		upstreamPort:     c.Upstream.Port,
		upstreamSSLMode:  c.Upstream.SSLMode,
		upstreamUser:     upstreamUser,
		upstreamPassword: upstreamPassword,
		upstreamDB:       c.Upstream.Database,
		clientUser:       c.Client.User,
		clientPassword:   clientPassword,
	}, nil
}

// QuoteIdent returns s formatted as a Postgres double-quoted identifier,
// suitable for safe interpolation into SQL like `SET ROLE "<ident>"`.
// Embedded `"` characters are doubled per Postgres lexical rules.
func QuoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"', '"')
		} else {
			out = append(out, s[i])
		}
	}
	out = append(out, '"')
	return string(out)
}
