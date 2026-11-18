# enzimOS AI provider gateway

Rust; one binary, `enzimos-ai-gateway`. Remote providers use rustls with the
system CA store.

Separate per-user service for explicitly selecting a local inference socket or an
OpenAI-compatible HTTPS endpoint. It does not load weights, detect hardware or
choose llama.cpp flags. It manages provider credentials and account sign-in.

Implemented: local chat/PCM-speech routing, explicitly enabled remote chat and
Responses protocol routes, streaming relay, private Unix IPC, credential-file
permission checks, output/connection bounds, disconnect cancellation. No implicit
local-to-cloud fallback: a failed local request does not transmit prompts elsewhere.
No provider credentials or prompt contents are logged or shipped in images.

`provider` chooses a configured provider; it is removed before sending the request.
The default is `local`. Remote endpoints use HTTPS. Loopback endpoints can use HTTP.
Responses and Chat are explicit capabilities; the gateway does not pretend their
request/event formats are identical. Cloud PCM speech adaptation remains future work.

## Experimental ChatGPT account adapter

A `chatgpt-login` provider (`{"kind": "chatgpt-login", "enabled": true}`) implements a
public-client-style account flow: dynamic
registration on the first sign-in (`dynamic_agent_client`, `agent_name_hint`
enzimOS, a stable per-host `ext_agent_host_id`), PKCE S256 and a loopback callback
on `127.0.0.1:1455` (another free port when that one is taken). No client ID or
secret is shipped, and no other program's auth cache is read.

- `POST /v1/accounts/chatgpt/login` `{"provider": NAME}` returns `authorize_url`
  for the browser; the callback and code exchange finish in the gateway.
- `GET /v1/accounts/chatgpt` returns `signed_in`, `email`, `waiting` and the last
  sign-in `error`.
- `POST /v1/accounts/chatgpt/logout` `{"provider": NAME}` revokes the refresh
  token (the discovery document's `revocation_endpoint`) and forgets the tokens.

Tokens are kept in `chatgpt-account.json` (mode 0600) beside the preferences file,
so sign-in needs `--preferences`. Access tokens are refreshed shortly before they
expire; the rotated refresh token replaces the old one, and refreshes are
serialized. The adapter checks issuer, audience, expiry and nonce on the ID token returned
directly by its TLS token exchange; it does not separately validate that token's
signature. The token only labels the account. A grant without
`chatgpt.tokens.use.direct` is refused.

Plan inference is Responses-only. Clients keep speaking Chat Completions:
requests become streamed, unstored Responses requests (system messages become
`instructions`, function tools one `enzimos` namespace), and the event stream is
translated back into `chat.completion.chunk` events ending in `[DONE]`. Usage-limit
and plan-unavailable failures are reported as such. The flow is tested against
loopback fixture auth and API servers. Real-account access and provider approval
have not been validated; fixture success is not a claim of supported account access.

`GET /v1/models[?provider=NAME]` lists a provider's models (default: the selected
one): the local runtime's list, an OpenAI-compatible endpoint's `/models`, or the
plan models with `visibility: list`.

```sh
enzimos-ai-gateway --config /path/providers.json \
  --socket /path/private-directory/service.sock
```

The socket directory must be private and owned. The packaged user unit starts with the enzUI session and reads `ai-providers.json` from the user manager’s XDG configuration directory. Use owned mode-0600 regular files for provider credentials. The same-UID boundary is not strong
isolation from hostile applications; sandboxed app enrollment/portals are later work.

## Typed preference control

`GET /v1/preferences` returns schema1, a content-derived `revision`, `persistent`
and redacted `preferences`. `POST /v1/preferences` accepts exactly
`{"schema_version":1,"revision":"<read revision>","preferences":{...}}`.
Unknown fields, unsupported values and unavailable providers/runtimes are refused.
HTTP409 means active work or a stale revision; re-read and review before retrying.
Preferences never interrupt an admitted gateway job.
Gateway selection never sends a request or falls back to another provider.

The gateway accepts only `default_provider`, selected from already configured,
enabled chat providers. This API cannot add provider endpoints, accounts,
credentials or an OAuth registration.

The optional `--preferences FILE` enables persistent mutations; its existing parent
must be owned mode0700. Files are owned mode0600, regular, single-link and opened
without following symlinks. Writes use an exclusive lock, atomic rename and fsync;
external edits cause a conflict until restart. Without this option the read API
works but mutation is unavailable. Sample units use a private `StateDirectory`
and `%S/<service>/preferences.json`; configuration/credentials stay read-only.

Settings must use its existing broker consent and call-liveness checks before
forwarding agent changes. The socket authenticates the account UID, not a specific
application: this API is not a replacement for sandbox admission or MCP consent.
Reads do not reveal model paths, credentials or endpoint URLs and do not load models.
No service is enabled or provisioned with models/accounts by this interface.

## Build and test

Requires Linux and Rust 1.95 or newer. Remote HTTPS uses the system CA store.

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked
cargo fmt --check
```

Tests use private sockets, temporary credentials and loopback provider fixtures.
They do not discover real credentials, contact paid providers or start host services.
`deploy/` supplies an opt-in user unit; building does not enable it.

## License

MIT; see [LICENSE](LICENSE).
