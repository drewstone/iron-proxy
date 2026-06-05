package postgres

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// dsnNode builds a non-zero yaml.Node so the upstream.dsn presence check
// (Kind != 0) passes. The stub buildSource ignores its contents.
func dsnNode(t *testing.T) yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("{type: env, var: X}"), &n))
	// Unmarshal yields a DocumentNode wrapping the mapping; unwrap it.
	require.NotEmpty(t, n.Content)
	return *n.Content[0]
}

// stubSource returns a no-op secrets.Source for every node, so Compile never
// touches a real backend.
func stubSource(yaml.Node, *slog.Logger) (secrets.Source, error) {
	return staticDSN{name: "stub", value: "host=db"}, nil
}

func TestCompile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("PG_PW", "secret")

	route := func(database string) RouteConfig {
		return RouteConfig{
			Database: database,
			Upstream: UpstreamConfig{DSN: dsnNode(t)},
			Client:   ClientConfig{User: "u", PasswordEnv: "PG_PW"},
			Role:     "r",
		}
	}

	t.Run("valid single listener many routes", func(t *testing.T) {
		listeners, err := Compile([]ListenerConfig{{
			Name:   "main",
			Listen: "127.0.0.1:0",
			Routes: []RouteConfig{route("analytics"), route("reporting")},
		}}, logger, stubSource)
		require.NoError(t, err)
		require.Len(t, listeners, 1)
		require.Equal(t, "main", listeners[0].Name())
		require.Equal(t, "analytics", listeners[0].Route("analytics").Database())
		require.Equal(t, "reporting", listeners[0].Route("reporting").Database())
		require.Nil(t, listeners[0].Route("missing"))
		require.True(t, listeners[0].Route("analytics").VerifyClient("u", "secret"))
	})

	t.Run("empty input is a no-op", func(t *testing.T) {
		listeners, err := Compile(nil, logger, stubSource)
		require.NoError(t, err)
		require.Nil(t, listeners)
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := Compile([]ListenerConfig{{Listen: "127.0.0.1:0", Routes: []RouteConfig{route("a")}}}, logger, stubSource)
		require.ErrorContains(t, err, "name is required")
	})

	t.Run("listen is required", func(t *testing.T) {
		_, err := Compile([]ListenerConfig{{Name: "main", Routes: []RouteConfig{route("a")}}}, logger, stubSource)
		require.ErrorContains(t, err, "listen is required")
	})

	t.Run("at least one route is required", func(t *testing.T) {
		_, err := Compile([]ListenerConfig{{Name: "main", Listen: "127.0.0.1:0"}}, logger, stubSource)
		require.ErrorContains(t, err, "at least one route is required")
	})

	t.Run("duplicate listener name rejected", func(t *testing.T) {
		l := ListenerConfig{Name: "main", Listen: "127.0.0.1:0", Routes: []RouteConfig{route("a")}}
		_, err := Compile([]ListenerConfig{l, l}, logger, stubSource)
		require.ErrorContains(t, err, "duplicate listener name")
	})

	t.Run("duplicate route database rejected", func(t *testing.T) {
		_, err := Compile([]ListenerConfig{{
			Name:   "main",
			Listen: "127.0.0.1:0",
			Routes: []RouteConfig{route("dup"), route("dup")},
		}}, logger, stubSource)
		require.ErrorContains(t, err, `duplicate route database "dup"`)
	})

	t.Run("route database is required", func(t *testing.T) {
		_, err := Compile([]ListenerConfig{{
			Name:   "main",
			Listen: "127.0.0.1:0",
			Routes: []RouteConfig{route("")},
		}}, logger, stubSource)
		require.ErrorContains(t, err, "database is required")
	})

	t.Run("route upstream dsn is required", func(t *testing.T) {
		r := route("a")
		r.Upstream.DSN = yaml.Node{}
		_, err := Compile([]ListenerConfig{{Name: "main", Listen: "127.0.0.1:0", Routes: []RouteConfig{r}}}, logger, stubSource)
		require.ErrorContains(t, err, "upstream.dsn is required")
	})

	t.Run("route client fields required", func(t *testing.T) {
		r := route("a")
		r.Client.User = ""
		_, err := Compile([]ListenerConfig{{Name: "main", Listen: "127.0.0.1:0", Routes: []RouteConfig{r}}}, logger, stubSource)
		require.ErrorContains(t, err, "client.user is required")

		r = route("a")
		r.Client.PasswordEnv = ""
		_, err = Compile([]ListenerConfig{{Name: "main", Listen: "127.0.0.1:0", Routes: []RouteConfig{r}}}, logger, stubSource)
		require.ErrorContains(t, err, "client.password_env is required")
	})

	t.Run("unset password env rejected", func(t *testing.T) {
		r := route("a")
		r.Client.PasswordEnv = "PG_PW_UNSET"
		_, err := Compile([]ListenerConfig{{Name: "main", Listen: "127.0.0.1:0", Routes: []RouteConfig{r}}}, logger, stubSource)
		require.ErrorContains(t, err, "is not set in the environment")
	})
}
