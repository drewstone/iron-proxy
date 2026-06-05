package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"

	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// staticSource is a no-op secrets.Source for building local test listeners.
type staticSource struct{ name, value string }

func (s staticSource) Name() string                        { return s.name }
func (s staticSource) Get(context.Context) (string, error) { return s.value, nil }

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// localListener builds a single-route local listener for conflict/passthrough
// tests.
func localListener(t *testing.T, name, database string) *postgres.Listener {
	t.Helper()
	r, err := postgres.NewManagedRoute(database, staticSource{name: "local", value: "host=local"}, "u", "p", "")
	require.NoError(t, err)
	l, err := postgres.NewListener(name, "127.0.0.1:0", []*postgres.Route{r})
	require.NoError(t, err)
	return l
}

func TestPgEnv(t *testing.T) {
	cases := []struct {
		foreignID, suffix, want string
	}{
		{"pg-analytics", "CLIENT_USER", "IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER"},
		{"PG.Main", "CLIENT_USER", "IRON_PROXY_PG_PG_MAIN_CLIENT_USER"},
		{"warehouse~1", "CLIENT_PASSWORD", "IRON_PROXY_PG_WAREHOUSE_1_CLIENT_PASSWORD"},
		{"already_snake", "CLIENT_PASSWORD", "IRON_PROXY_PG_ALREADY_SNAKE_CLIENT_PASSWORD"},
		{"db123", "CLIENT_USER", "IRON_PROXY_PG_DB123_CLIENT_USER"},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, pgEnv(c.foreignID, c.suffix), "pgEnv(%q,%q)", c.foreignID, c.suffix)
	}
}

func TestPostgresListenersFromSync_EnvPresent(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly"}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "s3cret",
	})

	listeners, ok := postgresListenersFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.Len(t, listeners, 1)
	require.Equal(t, managedPgListenerName, listeners[0].Name())
	require.Equal(t, "127.0.0.1:0", listeners[0].Listen())

	// The foreign_id is the routing database when none is supplied.
	route := listeners[0].Route("pg-analytics")
	require.NotNil(t, route)
	require.Equal(t, "readonly", route.Role())
	require.True(t, route.VerifyClient("app", "s3cret"))
}

func TestPostgresListenersFromSync_ExplicitDatabase(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listeners, ok := postgresListenersFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.Len(t, listeners, 1)
	// Routing key is the explicit database, not the foreign_id.
	require.NotNil(t, listeners[0].Route("analytics"))
	require.Nil(t, listeners[0].Route("pg-analytics"))
}

func TestPostgresListenersFromSync_NoRole(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pgmain","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                 "127.0.0.1:0",
		"IRON_PROXY_PG_PGMAIN_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PGMAIN_CLIENT_PASSWORD": "pw",
	})

	listeners, ok := postgresListenersFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.Len(t, listeners, 1)
	require.Empty(t, listeners[0].Route("pgmain").Role(), "absent role must be a no-op")
}

func TestPostgresListenersFromSync_MissingCredsSkipsRoute(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// IRON_PROXY_PG_LISTEN is set but client credentials are missing: the route
	// is skipped, and with no usable routes no managed listener is added.
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN": "127.0.0.1:0",
	})

	listeners, ok := postgresListenersFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Empty(t, listeners)
	require.Contains(t, logBuf.String(), "skipping synced postgres route")
}

func TestPostgresListenersFromSync_NoListenEnvKeepsLocal(t *testing.T) {
	local := localListener(t, "local-main", "appdb")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// Credentials present but IRON_PROXY_PG_LISTEN unset: no managed listener,
	// local listeners preserved.
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listeners, ok := postgresListenersFromSync([]*postgres.Listener{local}, getenv, logger, raw)
	require.True(t, ok)
	require.Equal(t, []*postgres.Listener{local}, listeners)
	require.Contains(t, logBuf.String(), "IRON_PROXY_PG_LISTEN not set")
}

func TestPostgresListenersFromSync_DuplicateDatabaseDropped(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"a","database":"shared","dsn":{"type":"env","var":"PG_DSN"}},
		{"id":"pgs_2","foreign_id":"b","database":"shared","dsn":{"type":"env","var":"PG_DSN"}}
	]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":            "127.0.0.1:0",
		"IRON_PROXY_PG_A_CLIENT_USER":     "app",
		"IRON_PROXY_PG_A_CLIENT_PASSWORD": "pw",
		"IRON_PROXY_PG_B_CLIENT_USER":     "app",
		"IRON_PROXY_PG_B_CLIENT_PASSWORD": "pw",
	})

	listeners, ok := postgresListenersFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Len(t, listeners, 1)
	require.NotNil(t, listeners[0].Route("shared"))
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenersFromSync_InvalidPayload(t *testing.T) {
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listeners, ok := postgresListenersFromSync(nil, mapEnv(nil), logger, json.RawMessage(`{not an array`))
	require.False(t, ok, "invalid payload must signal keep-current")
	require.Nil(t, listeners)
	require.Contains(t, logBuf.String(), "rejecting invalid postgres config")
}

func TestPostgresListenersFromSync_NullPayloadKeepsLocal(t *testing.T) {
	local := localListener(t, "local-main", "appdb")

	listeners, ok := postgresListenersFromSync([]*postgres.Listener{local}, mapEnv(nil), discardLogger(), json.RawMessage("null"))
	require.True(t, ok)
	require.Equal(t, []*postgres.Listener{local}, listeners)
}

func TestApplyPostgresSync_ReloadsListeners(t *testing.T) {
	mgr := postgres.NewManager(discardLogger())
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	applyPostgresSync(context.Background(), mgr, nil, getenv, discardLogger(), raw)
	require.Equal(t, []string{managedPgListenerName}, mgr.Names())
}

var _ secrets.Source = staticSource{}

func TestApplyPipelineSync_ValidConfig_Swaps(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	require.NotSame(t, original, holder.Load(), "pipeline should have been swapped")
	require.Equal(t, "allowlist", holder.Load().Names())
	require.Contains(t, logBuf.String(), "pipeline reloaded")
}

func TestApplyPipelineSync_InvalidJSON_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	applyPipelineSync(holder, transform.BodyLimits{}, logger, json.RawMessage(`{not json`), nil, nil)

	require.Same(t, original, holder.Load(), "pipeline must not be swapped on invalid config")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_InvalidRule_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// host and cidr are mutually exclusive — rule construction fails.
	rules := json.RawMessage(`[{"host":"example.com","cidr":"10.0.0.0/8"}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	require.Same(t, original, holder.Load(), "pipeline must not be swapped when transform construction fails")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_PreservesAuditFunc(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	called := false
	original.SetAuditFunc(func(*transform.PipelineResult) { called = true })
	holder := transform.NewPipelineHolder(original)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rules := json.RawMessage(`[{"host":"example.com"}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	holder.Load().EmitAudit(nil)
	require.True(t, called, "audit func should be carried over to the new pipeline")
}
