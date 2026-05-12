# 1Password Connect server for integration tests

This compose stack starts a self-hosted 1Password Connect server (the
`connect-api` and `connect-sync` containers, sharing a data volume) so the
`TestOnePasswordConnect` integration test can talk to a real Connect API.

## Required files

Drop a `1password-credentials.json` next to `docker-compose.yaml` before
starting the stack. The file is issued by 1Password when you provision a
Connect server in the account that owns the `iron-proxy-itests` vault. In CI,
this file is materialised from the `OP_CONNECT_CREDENTIALS_JSON` secret by the
workflow.

## Required GitHub Actions secrets

- `OP_CONNECT_CREDENTIALS_JSON` — full JSON contents of
  `1password-credentials.json`
- `OP_CONNECT_TOKEN` — Connect API access token granted to the same Connect
  server, with read access to `iron-proxy-itests`

The test reuses the same vault and item as `TestOnePassword`
(`op://iron-proxy-itests/itests-password/password` → `1password-example-password`).
