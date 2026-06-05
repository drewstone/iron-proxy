// Package postgres implements an iron-proxy listener that MITM-proxies
// PostgreSQL traffic so a static role policy is in effect on every query the
// upstream database sees.
//
// The listener accepts client connections, authenticates them against
// proxy-managed credentials, opens its own authenticated connection upstream
// (handling SCRAM/MD5 termination via pgconn), optionally issues a single
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
// call equivalents (`set_config('role', ...)`), and DO blocks. Multi-statement
// Simple Queries are allowed as long as every statement passes the role policy;
// a batch is rejected if any statement mutates the role or is a DO block.
// Extended Query, COPY, and prepared statements pass through unchanged.
//
// A single listener fronts multiple upstream databases: the top-level
// postgres: key is a list of listeners, and each listener holds a list of
// routes. A route is selected by the database name the client supplies in its
// startup message; each route has its own upstream DSN, client credentials,
// and optional injected role. One listen address therefore serves many
// databases. The proxy runs a single postgres listener: the top-level
// postgres: block is one object with a listen address and a list of routes.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// SourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type SourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// listenerName is the fixed name of the single postgres listener, surfaced in
// logs. The proxy runs at most one listener, so the name is not configurable.
const listenerName = "postgres"

// ListenerConfig is the top-level postgres: block — a single bind address
// fronting a set of database-keyed routes.
type ListenerConfig struct {
	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	Listen string `yaml:"listen"`

	// Routes is the set of upstream databases this listener fronts. A route is
	// selected by the database name the client sends in its startup message.
	// At least one route is required.
	Routes []RouteConfig `yaml:"routes"`
}

// RouteConfig describes one upstream database reachable through a listener. The
// client selects it by sending its Database value as the startup "database"
// parameter.
type RouteConfig struct {
	// Database is the routing key: the database name a client must request to
	// reach this upstream. Required and must be unique within a listener.
	Database string `yaml:"database"`

	// Upstream is the database the proxy connects to on behalf of clients
	// routed here.
	Upstream UpstreamConfig `yaml:"upstream"`

	// Client describes the credentials clients must present to use this route.
	// The proxy verifies a single shared user/password pair per route —
	// per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

	// Role is the Postgres role the proxy SETs at session start for this route.
	// When set, every query the client subsequently issues runs as this role on
	// the upstream database. Optional: when empty, the proxy issues no SET ROLE
	// and the upstream session runs as the connecting user.
	Role string `yaml:"role,omitempty"`
}

// UpstreamConfig describes the database the proxy forwards to. The DSN is
// loaded from any registered secret source (env, aws_sm, aws_ssm, 1password,
// 1password_connect) and is passed verbatim to pgconn.ParseConfig — both
// URL-style (postgres://user:pw@host:port/db?sslmode=...) and keyword/value
// strings (host=... port=... user=... password=... dbname=... sslmode=...)
// are accepted.
type UpstreamConfig struct {
	DSN yaml.Node `yaml:"dsn"`
}

// ClientConfig describes the credentials the proxy demands from clients.
type ClientConfig struct {
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
}

// Listener is the compiled, runtime form of a single ListenerConfig: a bind
// address and the database-keyed routes reachable through it.
type Listener struct {
	name   string
	listen string
	routes map[string]*Route
}

// Name returns the listener's name (a fixed identifier surfaced in logs).
func (l *Listener) Name() string { return l.name }

// Listen returns the bind address.
func (l *Listener) Listen() string { return l.listen }

// Route returns the route for the given database name, or nil if no route on
// this listener serves it.
func (l *Listener) Route(database string) *Route { return l.routes[database] }

// Routes returns all of the listener's routes. The order is unspecified.
func (l *Listener) Routes() []*Route {
	out := make([]*Route, 0, len(l.routes))
	for _, r := range l.routes {
		out = append(out, r)
	}
	return out
}

// Route is the compiled, runtime form of a single RouteConfig: one upstream
// database with its own credentials and optional injected role.
type Route struct {
	database string
	role     string

	upstreamDSN secrets.Source

	clientUser     string
	clientPassword string
}

// Database returns the route's routing key — the database name a client
// requests to reach this upstream.
func (r *Route) Database() string { return r.database }

// Role returns the role the proxy SETs upstream at session start. Empty
// means no role is set (the upstream session runs as the connecting user).
func (r *Route) Role() string { return r.role }

// UpstreamDSN returns the upstream connection string, fetched from the
// configured secret source. The result is cached by the source; repeated
// calls do not necessarily round-trip to the backend.
func (r *Route) UpstreamDSN(ctx context.Context) (string, error) {
	return r.upstreamDSN.Get(ctx)
}

// VerifyClient returns whether the given (user, password) pair matches the
// route's configured client credentials.
func (r *Route) VerifyClient(user, password string) bool {
	return user == r.clientUser && password == r.clientPassword
}

// ClientUser returns the user clients must present to use this route.
func (r *Route) ClientUser() string { return r.clientUser }

// LoadFromNode decodes the raw postgres: yaml.Node into a ListenerConfig and
// compiles it into a Listener. An empty node (the postgres: key absent from the
// source document) returns (nil, nil) so callers can treat "no postgres
// listener" as a normal case. An empty block (no listen and no routes) returns
// the same.
func LoadFromNode(node yaml.Node, logger *slog.Logger) (*Listener, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var c ListenerConfig
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding postgres config: %w", err)
	}
	return Compile(c, logger, secrets.BuildSource)
}

// Compile validates and compiles a ListenerConfig into a Listener. Returns
// (nil, nil) when the block is empty (no listen and no routes) so callers can
// treat "not configured" as a no-op without a sentinel error.
func Compile(c ListenerConfig, logger *slog.Logger, buildSource SourceBuilder) (*Listener, error) {
	if c.Listen == "" && len(c.Routes) == 0 {
		return nil, nil
	}
	if c.Listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
	}
	if len(c.Routes) == 0 {
		return nil, fmt.Errorf("postgres: at least one route is required")
	}

	routes := make(map[string]*Route, len(c.Routes))
	for j, rc := range c.Routes {
		rctx := fmt.Sprintf("postgres.routes[%d]", j)
		if rc.Database != "" {
			rctx = fmt.Sprintf("postgres.routes[%q]", rc.Database)
		}

		if rc.Database == "" {
			return nil, fmt.Errorf("%s: database is required", rctx)
		}
		if rc.Upstream.DSN.Kind == 0 {
			return nil, fmt.Errorf("%s: upstream.dsn is required", rctx)
		}
		if rc.Client.User == "" {
			return nil, fmt.Errorf("%s: client.user is required", rctx)
		}
		if rc.Client.PasswordEnv == "" {
			return nil, fmt.Errorf("%s: client.password_env is required", rctx)
		}
		if _, ok := routes[rc.Database]; ok {
			return nil, fmt.Errorf("postgres: duplicate route database %q", rc.Database)
		}

		dsnSource, err := buildSource(rc.Upstream.DSN, logger)
		if err != nil {
			return nil, fmt.Errorf("%s: building upstream.dsn source: %w", rctx, err)
		}

		clientPassword := os.Getenv(rc.Client.PasswordEnv)
		if clientPassword == "" {
			return nil, fmt.Errorf("%s: client.password_env %q is not set in the environment", rctx, rc.Client.PasswordEnv)
		}

		routes[rc.Database] = &Route{
			database:       rc.Database,
			role:           rc.Role,
			upstreamDSN:    dsnSource,
			clientUser:     rc.Client.User,
			clientPassword: clientPassword,
		}
	}

	return &Listener{
		name:   listenerName,
		listen: c.Listen,
		routes: routes,
	}, nil
}

// NewListener builds the postgres listener from a bind address and a set of
// routes. It is the construction path for control-plane-synced listeners, whose
// routes are built one at a time via NewManagedRoute. The listen address is
// required, and at least one route must be supplied; a route whose Database
// collides with an earlier one is an error.
func NewListener(listen string, routes []*Route) (*Listener, error) {
	if listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("postgres: at least one route is required")
	}
	m := make(map[string]*Route, len(routes))
	for _, r := range routes {
		if _, ok := m[r.database]; ok {
			return nil, fmt.Errorf("postgres: duplicate route database %q", r.database)
		}
		m[r.database] = r
	}
	return &Listener{name: listenerName, listen: listen, routes: m}, nil
}

// NewManagedRoute builds a Route for a control-plane-synced listener. The
// upstream DSN source and optional role come from the control plane; the client
// credentials come from the proxy's environment. Unlike the YAML path,
// clientPassword is the literal password value, not the name of an env var —
// managed mode has no second level of indirection. All fields except role are
// required.
func NewManagedRoute(database string, dsn secrets.Source, clientUser, clientPassword, role string) (*Route, error) {
	if database == "" {
		return nil, fmt.Errorf("postgres: managed route database is required")
	}
	ctx := fmt.Sprintf("postgres route[%q]", database)
	if dsn == nil {
		return nil, fmt.Errorf("%s: dsn source is required", ctx)
	}
	if clientUser == "" {
		return nil, fmt.Errorf("%s: client user is required", ctx)
	}
	if clientPassword == "" {
		return nil, fmt.Errorf("%s: client password is required", ctx)
	}
	return &Route{
		database:       database,
		role:           role,
		upstreamDSN:    dsn,
		clientUser:     clientUser,
		clientPassword: clientPassword,
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
