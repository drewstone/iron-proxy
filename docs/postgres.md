# Postgres listener

iron-proxy's `postgres:` block configures one or more MITM listeners that sit
between clients and a PostgreSQL database. Each listener authenticates
clients against proxy-managed credentials, opens its own authenticated
connection to the upstream database, issues `SET ROLE "<role>"` on that
session, then relays the wire protocol transparently. The intended use case
is identity-aware DB access: the application connects as a shared
service-account role, the proxy switches that session to a per-tenant role,
and PostgreSQL row-level security (or column-level grants) scope access
accordingly.

## Required: PgBouncer in session-pool mode

> [!IMPORTANT]
> If PgBouncer (or any other connection pooler) sits between iron-proxy and
> PostgreSQL, it **must** be configured in `pool_mode = session`. Running
> iron-proxy against a transaction-mode or statement-mode bouncer silently
> defeats the role policy.

### Why

iron-proxy issues `SET ROLE` once per connection. The role persists for the
lifetime of that backend session on the database. The proxy's security model
assumes the backend the role was set on is the same backend that subsequently
runs the client's queries.

PgBouncer's pool modes break that assumption to different degrees:

| Pool mode      | Backend binding                                | Compatible with iron-proxy? |
|----------------|------------------------------------------------|-----------------------------|
| `session`      | One backend pinned for entire client session   | **Yes**                     |
| `transaction`  | Backend released between transactions          | **No** — silently broken    |
| `statement`    | Backend released between statements            | **No** — silently broken    |

In transaction or statement pooling, the `SET ROLE` we issue lands on
backend A; the client's next autocommit query may land on backend B which
does not have the role set. The query then runs as the upstream
service-account user (typically a superuser) — bypassing every RLS policy
that relies on `current_role`. There's no protocol-level signal of this; the
proxy and the application both see "ok" responses, the database happily
serves the data, and your tenant boundaries quietly evaporate.

### Configuring PgBouncer

In your `pgbouncer.ini`:

```ini
[pgbouncer]
pool_mode = session
```

If you have per-database overrides in `[databases]`, ensure none of them
override `pool_mode` to a non-session value.

After changing pool mode, restart PgBouncer (or `RELOAD` from the admin
console) and verify with `SHOW CONFIG` on the bouncer admin DB:

```
$ psql -h <pgbouncer-host> -p 6432 -U pgbouncer pgbouncer
pgbouncer=# SHOW CONFIG;
   key       | value
-------------+---------
 pool_mode   | session
 ...
```

### Verifying iron-proxy + PgBouncer end-to-end

Connect through iron-proxy and run `SELECT current_role` twice as separate
autocommit queries. In session mode it returns the configured role both
times. If it ever returns the upstream service-account user, the deployment
is misconfigured — fix the bouncer pool mode before exposing the listener.

```sql
SELECT current_role;  -- expect: tenant_role
SELECT current_role;  -- expect: tenant_role
```

We considered baking that check into the proxy as an automatic startup
probe but removed it: false positives on cold pools were annoying, and
deployment-time verification is cheap and explicit.

## What the proxy enforces

The relay rejects (with a synthetic Postgres `ErrorResponse`, so the
connection stays usable) any client SQL that would override the injected
role. The check parses each Simple Query and Extended Query `Parse` with
libpg_query and walks the AST, so the rejection covers indirect bypasses,
not just literal `SET ROLE`:

- `SET ROLE` / `RESET ROLE` / `SET LOCAL ROLE` / `SET SESSION ROLE`
- `SET SESSION AUTHORIZATION` / `RESET SESSION AUTHORIZATION`
- `SELECT set_config('role', ...)` and the `pg_catalog.set_config(...)` form
- Equivalent `set_config('session_authorization', ...)` calls
- The above nested inside CTEs, subqueries, function arguments, etc.
- `DO $$ ... $$` blocks (plpgsql is opaque to the SQL parser; rejecting outright is the only safe call)
- Multi-statement Simple Queries

## What the proxy cannot enforce

These have to be defended at the database layer with the right role grants:

- **User-defined `SECURITY DEFINER` functions** that elevate inside the function body.
- **Dynamic SQL** via plpgsql `EXECUTE format('SET ROLE %I', var)` where the role string is computed at runtime.
- **Wrapper functions** that call `set_config` under a different name.

The proxy is one layer of defense against role-mutation on the wire. Real
multi-tenant isolation also requires:

1. The upstream user iron-proxy authenticates as should be a **non-superuser**
   that has been granted membership in the per-tenant roles. Superusers
   bypass RLS regardless of `SET ROLE`. (In the test fixture we use a
   superuser only because `SET ROLE` to a non-superuser drops the bypass —
   that works, but is unusual.)
2. RLS policies on every table that contains tenant-scoped data, keyed on
   `current_role`.
3. Audits to confirm `pg_proc.prosecdef` (SECURITY DEFINER) functions only
   exist where intentional and cannot reach across tenants.

## Other limitations

- **No client→proxy TLS.** `SSLRequest` from the client is refused with `N`;
  clients should connect with `sslmode=disable` or `sslmode=prefer`. TLS
  to the upstream database is independent and supported via
  `upstream.sslmode: require`.
- **CancelRequest is not forwarded.** The proxy advertises a synthetic
  `BackendKeyData` and ignores cancel requests targeted at it.
- **One shared client credential per listener.** Per-user proxy auth is not
  supported.
- **`pg_stat_statements` and query logs** see exactly what the client sent;
  the proxy doesn't rewrite or add statements.

## Example config

```yaml
postgres:
  - name: tenant-db
    listen: ":5432"
    upstream:
      host: pgbouncer.internal   # session-mode bouncer in front of Postgres
      port: 6432
      sslmode: require
      user_env: PG_UPSTREAM_USER
      password_env: PG_UPSTREAM_PASSWORD
      database: appdb
    client:
      user: app_user
      password_env: PG_PROXY_PASSWORD
    role: tenant_role
```

See [`iron-proxy.example.yaml`](../iron-proxy.example.yaml) for the fully
annotated form, including how to run multiple listeners from one proxy.
