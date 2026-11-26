// SPDX-License-Identifier: MIT
//! Sign in with ChatGPT and plan inference.
//!
//! Sign-in is the documented public-client flow: dynamic registration on the
//! first sign-in (`dynamic_agent_client`), PKCE, and a loopback callback on
//! 127.0.0.1. Tokens live in one private file in the gateway's state folder and
//! never leave this process. The ID token comes straight from the token
//! endpoint over TLS, so its claims are checked without a signature check
//! (OpenID Connect Core 3.1.3.7); it only names the account.
//!
//! Plan inference is only offered through the Responses API (streamed, not
//! stored). Clients speak Chat Completions to the gateway; requests and the
//! event stream are translated here.
use crate::{
    Failure, http,
    upstream::{self, Endpoint, Response},
};
use serde_json::{Map, Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const AUTH: &str = "https://auth.openai.com";
const API: &str = "https://api.openai.com/v1";
/// The `resource` every authorization and token request names.
const RESOURCE: &str = "https://api.openai.com/v1";
const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
const CALLBACK: &str = "/auth/callback";
const PORT: u16 = 1455;
/// The namespace this gateway's clients' function tools are offered in.
const NAMESPACE: &str = "enzimos";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn random(bytes: usize) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut buffer = vec![0u8; bytes];
    ring::rand::SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| "no system randomness".to_owned())?;
    Ok(base64url(&buffer))
}

fn base64url(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for group in data.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=group.len() {
            out.push(char::from(TABLE[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

fn unbase64url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.trim_end_matches('=').bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        bits = bits << 6 | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count & 0xff) as u8);
        }
    }
    Some(out)
}

/// The claims of a JWT, unverified.
fn claims(token: &str) -> Option<Value> {
    serde_json::from_slice(&unbase64url(token.split('.').nth(1)?)?).ok()
}

/// A `chatgpt-login` provider's endpoints; `auth_url`/`api_url` exist for
/// loopback test servers and default to OpenAI's.
struct Provider {
    auth: Endpoint,
    issuer: String,
    api: Endpoint,
}

impl Provider {
    fn new(config: &Value) -> Result<Self, String> {
        let issuer = config["auth_url"]
            .as_str()
            .unwrap_or(AUTH)
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            auth: Endpoint::parse(&issuer)?,
            api: Endpoint::parse(config["api_url"].as_str().unwrap_or(API))?,
            issuer,
        })
    }
}

/// The signed-in account and the sign-in in progress.
pub(crate) struct Accounts {
    file: PathBuf,
    /// Serializes refreshes: refresh tokens rotate.
    lock: tokio::sync::Mutex<()>,
    /// The sign-in in progress (`Some(None)`) or how the last one failed.
    attempt: std::sync::Mutex<Option<Option<String>>>,
    waiting: AtomicBool,
}

impl Accounts {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            file: directory.join("chatgpt-account.json"),
            lock: tokio::sync::Mutex::new(()),
            attempt: std::sync::Mutex::new(None),
            waiting: AtomicBool::new(false),
        }
    }

    /// The account file: private, owned like its folder, not a link.
    fn load(&self) -> Value {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let read = || -> Option<Value> {
            let owner = std::fs::metadata(self.file.parent()?).ok()?.uid();
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&self.file)
                .ok()?;
            let m = file.metadata().ok()?;
            if !m.is_file() || m.uid() != owner || m.mode() & 0o077 != 0 || m.len() > 65536 {
                return None;
            }
            let mut raw = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut raw).ok()?;
            serde_json::from_slice(&raw).ok().filter(Value::is_object)
        };
        read().unwrap_or_else(|| json!({}))
    }

    fn store(&self, account: &Value) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let temporary = self.file.with_extension("new");
        let _ = std::fs::remove_file(&temporary);
        let written = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, account.to_string().as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.file)
        })();
        let _ = std::fs::remove_file(&temporary);
        written.map_err(|_| "account state unavailable".to_owned())
    }

    /// What Settings shows: the account, and a sign-in in progress or its failure.
    pub(crate) fn status(&self) -> Value {
        let account = self.load();
        let attempt = self.attempt.lock().map(|a| a.clone()).unwrap_or_default();
        json!({
            "signed_in": account["refresh_token"].is_string(),
            "email": account["email"],
            "waiting": self.waiting.load(Ordering::SeqCst),
            "error": attempt.flatten(),
        })
    }

    /// Start a sign-in: listen on the loopback callback and return the page
    /// the user opens. The flow finishes in the background.
    pub(crate) async fn begin(self: &Arc<Self>, config: &Value) -> Result<Value, String> {
        let provider = Provider::new(config)?;
        if self.waiting.swap(true, Ordering::SeqCst) {
            return Err("a ChatGPT sign-in is already waiting".into());
        }
        let started = async {
            let mut account = self.load();
            if !account["host_id"].is_string() {
                account["host_id"] = json!(random(16)?);
                self.store(&account)?;
            }
            // Only the port of the registered callback may change later.
            let listener = match TcpListener::bind(("127.0.0.1", PORT)).await {
                Ok(listener) => listener,
                Err(_) => TcpListener::bind(("127.0.0.1", 0))
                    .await
                    .map_err(|_| "no loopback port for the sign-in".to_owned())?,
            };
            let port = listener
                .local_addr()
                .map_err(|_| "no loopback port".to_owned())?
                .port();
            let redirect = format!("http://127.0.0.1:{port}{CALLBACK}");
            let verifier = random(32)?;
            let challenge = base64url(
                ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref(),
            );
            let (state, nonce) = (random(16)?, random(16)?);
            let registered = account["client_id"].as_str().map(str::to_owned);
            let mut pairs = vec![
                (
                    "client_id",
                    registered
                        .clone()
                        .unwrap_or_else(|| "dynamic_agent_client".into()),
                ),
                (
                    "ext_agent_host_id",
                    account["host_id"].as_str().unwrap_or_default().to_owned(),
                ),
                ("response_type", "code".into()),
                ("redirect_uri", redirect.clone()),
                ("scope", SCOPE.into()),
                ("resource", RESOURCE.into()),
                ("state", state.clone()),
                ("nonce", nonce.clone()),
                ("code_challenge_method", "S256".into()),
                ("code_challenge", challenge),
            ];
            if registered.is_none() {
                pairs.push(("agent_name_hint", "enzimOS".into()));
            }
            for (key, field) in [("login_hint", "email"), ("id_token_hint", "id_token")] {
                if let (Some(_), Some(value)) = (&registered, account[field].as_str()) {
                    pairs.push((key, value.to_owned()));
                }
            }
            let borrowed = pairs
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>();
            let url = format!(
                "{}/api/accounts/authorize?{}",
                provider.issuer,
                upstream::form(&borrowed)
            );
            Ok::<_, String>((
                listener,
                url,
                Flow {
                    provider,
                    redirect,
                    verifier,
                    state,
                    nonce,
                    registered,
                },
            ))
        }
        .await;
        let (listener, url, flow) = match started {
            Ok(started) => started,
            Err(error) => {
                self.waiting.store(false, Ordering::SeqCst);
                return Err(error);
            }
        };
        if let Ok(mut attempt) = self.attempt.lock() {
            *attempt = Some(None);
        }
        let accounts = Arc::clone(self);
        tokio::spawn(async move {
            let result = match tokio::time::timeout(
                Duration::from_secs(600),
                callback(&listener, &flow.state),
            )
            .await
            {
                Ok(Ok((code, client_id))) => accounts.exchange(&flow, &code, client_id).await,
                Ok(Err(error)) => Err(error),
                Err(_) => Err("the sign-in was not finished in time".into()),
            };
            if let Ok(mut attempt) = accounts.attempt.lock() {
                *attempt = Some(result.err());
            }
            accounts.waiting.store(false, Ordering::SeqCst);
        });
        Ok(json!({"authorize_url": url}))
    }

    async fn exchange(
        &self,
        flow: &Flow,
        code: &str,
        client_id: Option<String>,
    ) -> Result<(), String> {
        let client_id = client_id
            .or_else(|| flow.registered.clone())
            .ok_or("the sign-in returned no client registration")?;
        let tokens = token_request(
            &flow.provider,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", code),
                ("code_verifier", &flow.verifier),
                ("redirect_uri", &flow.redirect),
                ("resource", RESOURCE),
            ],
        )
        .await?;
        let id = claims(tokens["id_token"].as_str().unwrap_or_default())
            .ok_or("the sign-in returned no identity")?;
        let audience = match &id["aud"] {
            Value::Array(list) => list.contains(&json!(client_id)),
            other => other == &json!(client_id),
        };
        if id["iss"].as_str().map(|i| i.trim_end_matches('/'))
            != Some(flow.provider.issuer.as_str())
            || !audience
            || id["exp"].as_u64().is_none_or(|exp| exp <= now())
            || id["nonce"].as_str() != Some(flow.nonce.as_str())
        {
            return Err("the sign-in identity did not match this request".into());
        }
        let _guard = self.lock.lock().await;
        let mut account = self.load();
        account["client_id"] = json!(client_id);
        account["email"] = id["email"].clone();
        account["id_token"] = tokens["id_token"].clone();
        keep(&mut account, &tokens)?;
        self.store(&account)
    }

    /// A current access token, refreshed when it is about to expire.
    async fn access_token(&self, config: &Value) -> Result<String, Failure> {
        let _guard = self.lock.lock().await;
        let mut account = self.load();
        let signed_out = || Failure::Bad("sign in to ChatGPT in Settings first".into());
        let refresh = account["refresh_token"]
            .as_str()
            .ok_or_else(signed_out)?
            .to_owned();
        if account["expires_at"]
            .as_u64()
            .is_some_and(|at| at > now() + 120)
        {
            return account["access_token"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(signed_out);
        }
        let provider = Provider::new(config).map_err(Failure::Bad)?;
        let client_id = account["client_id"].as_str().unwrap_or_default().to_owned();
        let tokens = token_request(
            &provider,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &refresh),
                ("resource", RESOURCE),
            ],
        )
        .await;
        let tokens = match tokens {
            Ok(tokens) => tokens,
            Err(error) if error == "invalid_grant" => {
                forget(&mut account);
                let _ = self.store(&account);
                return Err(Failure::Bad(
                    "the ChatGPT sign-in has expired; sign in again in Settings".into(),
                ));
            }
            Err(_) => return Err(Failure::Unavailable),
        };
        keep(&mut account, &tokens).map_err(Failure::Bad)?;
        self.store(&account).map_err(Failure::Bad)?;
        account["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(signed_out)
    }

    /// Sign out: revoke the refresh token and forget the tokens; the
    /// registration and host identity stay for the next sign-in.
    pub(crate) async fn sign_out(&self, config: &Value) -> Result<Value, String> {
        let provider = Provider::new(config)?;
        let _guard = self.lock.lock().await;
        let mut account = self.load();
        let mut revoked = false;
        if let (Some(token), Some(client_id)) = (
            account["refresh_token"].as_str(),
            account["client_id"].as_str(),
        ) {
            revoked = revoke(&provider, token, client_id).await.is_ok();
        }
        forget(&mut account);
        self.store(&account)?;
        Ok(json!({"signed_in": false, "revoked": revoked}))
    }

    /// The models the plan offers (`visibility: list`), as `/v1/models` lists them.
    pub(crate) async fn models(&self, config: &Value) -> Result<Value, Failure> {
        let token = self.access_token(config).await?;
        let provider = Provider::new(config).map_err(Failure::Bad)?;
        let request = provider.api.request(
            "GET",
            "/models",
            &[("Authorization".into(), format!("Bearer {token}"))],
            None,
        );
        let (status, body) = provider.api.fetch(&request).await?;
        if status != 200 {
            return Err(Failure::Unavailable);
        }
        let listed: Value = serde_json::from_slice(&body).map_err(|_| Failure::Unavailable)?;
        let models = listed["models"]
            .as_array()
            .or_else(|| listed["data"].as_array())
            .into_iter()
            .flatten()
            .filter(|m| m.get("visibility").is_none_or(|v| v == "list"))
            .filter_map(|m| m["slug"].as_str().or_else(|| m["id"].as_str()))
            .map(|slug| json!({"id": slug, "object": "model"}))
            .collect::<Vec<_>>();
        Ok(json!({"object": "list", "data": models}))
    }

    /// Answer one Chat Completions request through the plan's Responses API,
    /// streaming `chat.completion.chunk` events to `writer`.
    pub(crate) async fn relay(
        &self,
        config: &Value,
        body: &Value,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        started: &Arc<AtomicBool>,
    ) -> Result<(), Failure> {
        let request = responses_body(body).map_err(Failure::Bad)?;
        let token = self.access_token(config).await?;
        let provider = Provider::new(config).map_err(Failure::Bad)?;
        let raw = serde_json::to_vec(&request).map_err(|_| Failure::Unavailable)?;
        let message = provider.api.request(
            "POST",
            "/responses",
            &[
                ("Authorization".into(), format!("Bearer {token}")),
                ("Accept".into(), "text/event-stream".into()),
            ],
            Some(("application/json", &raw)),
        );
        let mut upstream = provider.api.connect().await?;
        crate::step(30, async {
            upstream.write_all(&message).await?;
            upstream.flush().await
        })
        .await?;
        let mut response = Response::default();
        let mut translator = Translator::default();
        let mut chunk = vec![0u8; 65536];
        let mut total = 0usize;
        loop {
            let n = crate::step(180, upstream.read(&mut chunk)).await?;
            let mut decoded = Vec::new();
            if n > 0 {
                total += n;
                if total > 8 * 1024 * 1024 {
                    return Err(Failure::Bad("provider output exceeds bound".into()));
                }
                response
                    .push(&chunk[..n], &mut decoded)
                    .map_err(Failure::Bad)?;
            }
            match response.status {
                None if n == 0 => return Err(Failure::Unavailable),
                None => continue,
                Some(200) => {}
                Some(status) => {
                    return Err(match status {
                        401 | 403 => Failure::Bad(
                            "ChatGPT refused the sign-in; sign in again in Settings".into(),
                        ),
                        429 => Failure::Bad("the ChatGPT plan's usage limit is reached".into()),
                        _ => Failure::Unavailable,
                    });
                }
            }
            if !started.swap(true, Ordering::SeqCst) {
                writer
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(|_| Failure::Closed)?;
            }
            let out = translator.feed(&decoded).map_err(Failure::Bad)?;
            if !out.is_empty() {
                writer.write_all(&out).await.map_err(|_| Failure::Closed)?;
            }
            if translator.done || n == 0 || response.finished() {
                // A stream that ends without `response.completed` is cut
                // short: the missing `[DONE]` tells the client so.
                return if translator.done {
                    Ok(())
                } else {
                    Err(Failure::Unavailable)
                };
            }
        }
    }
}

struct Flow {
    provider: Provider,
    redirect: String,
    verifier: String,
    state: String,
    nonce: String,
    registered: Option<String>,
}

fn keep(account: &mut Value, tokens: &Value) -> Result<(), String> {
    let access = tokens["access_token"]
        .as_str()
        .ok_or("the sign-in returned no access")?;
    let scope = tokens["scope"]
        .as_str()
        .or_else(|| tokens["scopes"].as_str());
    if scope.is_some_and(|s| !s.split(' ').any(|s| s == PLAN_SCOPE)) {
        return Err("this account did not allow ChatGPT plan use".into());
    }
    account["access_token"] = json!(access);
    account["expires_at"] = json!(now() + tokens["expires_in"].as_u64().unwrap_or(3600));
    if let Some(refresh) = tokens["refresh_token"].as_str() {
        account["refresh_token"] = json!(refresh);
    }
    if !account["refresh_token"].is_string() {
        return Err("the sign-in returned no lasting access".into());
    }
    Ok(())
}

fn forget(account: &mut Value) {
    if let Some(account) = account.as_object_mut() {
        for key in ["access_token", "refresh_token", "id_token", "expires_at"] {
            account.remove(key);
        }
    }
}

/// POST a token request; an OAuth error comes back as its `error` code.
async fn token_request(provider: &Provider, pairs: &[(&str, &str)]) -> Result<Value, String> {
    let form = upstream::form(pairs);
    let request = provider.auth.request(
        "POST",
        "/api/accounts/oauth/token",
        &[("Accept".into(), "application/json".into())],
        Some(("application/x-www-form-urlencoded", form.as_bytes())),
    );
    let (status, body) = provider
        .auth
        .fetch(&request)
        .await
        .map_err(|_| "the sign-in service is unreachable".to_owned())?;
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if status != 200 {
        return Err(value["error"]
            .as_str()
            .unwrap_or("the sign-in service refused")
            .to_owned());
    }
    Ok(value)
}

async fn revoke(provider: &Provider, token: &str, client_id: &str) -> Result<(), String> {
    let request = provider
        .auth
        .request("GET", "/.well-known/openid-configuration", &[], None);
    let (_, body) = provider
        .auth
        .fetch(&request)
        .await
        .map_err(|_| "unreachable".to_owned())?;
    let discovery: Value = serde_json::from_slice(&body).map_err(|_| "no discovery".to_owned())?;
    let url = discovery["revocation_endpoint"]
        .as_str()
        .ok_or("no revocation endpoint")?;
    let endpoint = Endpoint::parse(url)?;
    if endpoint.host != provider.auth.host {
        return Err("revocation endpoint on another host".into());
    }
    let form = upstream::form(&[
        ("token", token),
        ("token_type_hint", "refresh_token"),
        ("client_id", client_id),
    ]);
    let request = endpoint.request(
        "POST",
        "",
        &[],
        Some(("application/x-www-form-urlencoded", form.as_bytes())),
    );
    match endpoint.fetch(&request).await {
        Ok((200, _)) => Ok(()),
        _ => Err("not revoked".into()),
    }
}

/// Wait for the browser's return to the loopback callback; answers every
/// request with a small page and returns the code and issued client id.
async fn callback(listener: &TcpListener, state: &str) -> Result<(String, Option<String>), String> {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(request) = http::read_head(&mut stream).await else {
            continue;
        };
        let (path, query) = request
            .path
            .split_once('?')
            .unwrap_or((request.path.as_str(), ""));
        if request.method != "GET" || path != CALLBACK {
            let _ = page(&mut stream, 404, "Not found.").await;
            continue;
        }
        let pairs = upstream::query(query);
        if pairs.get("state").map(String::as_str) != Some(state) {
            let _ = page(
                &mut stream,
                400,
                "This sign-in link is out of date. Start the sign-in again in Settings.",
            )
            .await;
            continue;
        }
        if let Some(error) = pairs.get("error") {
            let _ = page(
                &mut stream,
                200,
                "The sign-in was cancelled. You can close this window.",
            )
            .await;
            return Err(if error == "access_denied" {
                "the sign-in was declined".into()
            } else {
                format!("the sign-in failed ({error})")
            });
        }
        let code = pairs
            .get("code")
            .cloned()
            .ok_or("the sign-in returned no code")?;
        let _ = page(
            &mut stream,
            200,
            "Signed in to ChatGPT. You can close this window and return to enzimOS.",
        )
        .await;
        return Ok((code, pairs.get("client_id").cloned()));
    }
}

async fn page(stream: &mut tokio::net::TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>enzimOS</title><body style=\"font:16px system-ui;margin:3em\"><p>{text}</p>"
    );
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

/// A Chat Completions request as a plan Responses request: system messages
/// become `instructions`, tools one namespace, and the request is streamed
/// and not stored, as plan use requires.
pub(crate) fn responses_body(chat: &Value) -> Result<Value, String> {
    let model = chat["model"]
        .as_str()
        .filter(|m| !m.is_empty())
        .ok_or("model required")?;
    let tools = chat["tools"].as_array().cloned().unwrap_or_default();
    let mut instructions = Vec::new();
    let mut input = Vec::new();
    let text = |content: &Value| match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    };
    let user_content = |content: &Value| -> Result<Value, String> {
        let Some(parts) = content.as_array() else {
            return Ok(json!(text(content)));
        };
        let mut translated = Vec::with_capacity(parts.len());
        for part in parts {
            translated.push(match part["type"].as_str() {
                Some("text") => json!({"type": "input_text", "text": part["text"].as_str().ok_or("message text required")?}),
                Some("image_url") => {
                    let url = part["image_url"]["url"]
                        .as_str()
                        .filter(|url| url.starts_with("data:image/jpeg;base64,") || url.starts_with("data:image/png;base64,"))
                        .ok_or("embedded screenshot image required")?;
                    json!({"type": "input_image", "image_url": url, "detail": "auto"})
                }
                _ => return Err("unsupported user content part".into()),
            });
        }
        Ok(json!(translated))
    };
    for message in chat["messages"].as_array().ok_or("messages required")? {
        match message["role"].as_str().unwrap_or_default() {
            "system" | "developer" => instructions.push(text(&message["content"])),
            "user" => input.push(json!({"role": "user", "content": user_content(&message["content"])?})),
            "assistant" => {
                let said = text(&message["content"]);
                if !said.is_empty() {
                    input.push(json!({"role": "assistant", "content": said}));
                }
                for call in message["tool_calls"].as_array().into_iter().flatten() {
                    let mut item = json!({"type": "function_call", "call_id": call["id"], "name": call["function"]["name"], "arguments": call["function"]["arguments"]});
                    if !tools.is_empty() {
                        item["namespace"] = json!(NAMESPACE);
                    }
                    input.push(item);
                }
            }
            "tool" => input.push(json!({"type": "function_call_output", "call_id": message["tool_call_id"], "output": text(&message["content"])})),
            _ => return Err("unsupported message role".into()),
        }
    }
    let mut request = Map::new();
    request.insert("model".into(), json!(model));
    if !instructions.is_empty() {
        request.insert("instructions".into(), json!(instructions.join("\n\n")));
    }
    request.insert("input".into(), Value::Array(input));
    if !tools.is_empty() {
        let functions = tools
            .iter()
            .filter(|t| t["type"] == "function")
            .map(|t| {
                let f = &t["function"];
                json!({"type": "function", "name": f["name"], "description": f["description"], "parameters": f["parameters"]})
            })
            .collect::<Vec<_>>();
        request.insert(
            "tools".into(),
            json!([{"type": "namespace", "name": NAMESPACE, "description": "Tools of the enzimOS assistant", "tools": functions}]),
        );
    }
    request.insert("stream".into(), json!(true));
    request.insert("store".into(), json!(false));
    Ok(Value::Object(request))
}

/// Responses stream events as `chat.completion.chunk` events.
#[derive(Default)]
pub(crate) struct Translator {
    line: Vec<u8>,
    calls: usize,
    pub(crate) done: bool,
}

impl Translator {
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let chunk = |delta: Value, out: &mut Vec<u8>| {
            let event = json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta}]});
            out.extend_from_slice(format!("data: {event}\n\n").as_bytes());
        };
        for &byte in bytes {
            if byte != b'\n' {
                if self.line.len() > 4 * 1024 * 1024 {
                    return Err("provider event exceeds bound".into());
                }
                self.line.push(byte);
                continue;
            }
            let line = std::mem::take(&mut self.line);
            let line = String::from_utf8_lossy(&line);
            let Some(data) = line
                .trim_end_matches('\r')
                .strip_prefix("data:")
                .map(str::trim)
            else {
                continue;
            };
            let Ok(event) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            match event["type"].as_str().unwrap_or_default() {
                "response.output_text.delta" => chunk(json!({"content": event["delta"]}), &mut out),
                "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                    chunk(json!({"reasoning_content": event["delta"]}), &mut out);
                }
                "response.output_item.done" if event["item"]["type"] == "function_call" => {
                    let item = &event["item"];
                    chunk(
                        json!({"tool_calls": [{"index": self.calls, "id": item["call_id"], "type": "function",
                            "function": {"name": item["name"], "arguments": item["arguments"]}}]}),
                        &mut out,
                    );
                    self.calls += 1;
                }
                "response.completed" => {
                    out.extend_from_slice(b"data: [DONE]\n\n");
                    self.done = true;
                    return Ok(out);
                }
                "response.failed" | "response.incomplete" | "error" => {
                    let error = &event["response"]["error"];
                    let code = error["code"]
                        .as_str()
                        .or_else(|| event["code"].as_str())
                        .unwrap_or("response failed");
                    return Err(match code {
                        "subscription_sharing_usage_limit_exceeded" => {
                            "the ChatGPT plan's usage limit is reached".into()
                        }
                        "subscription_sharing_usage_unavailable" => {
                            "ChatGPT plan use is unavailable for this account".into()
                        }
                        code => format!("ChatGPT: {code}"),
                    });
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) fn base64url(data: &[u8]) -> String {
        super::base64url(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_requests_become_plan_responses_requests() {
        let chat = json!({"model": "gpt-5", "stream": true, "max_tokens": 9, "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "read a"},
            {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "file_read", "arguments": "{\"path\":\"a\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "{\"ok\":true}"}],
            "tools": [{"type": "function", "function": {"name": "file_read", "description": "Read", "parameters": {"type": "object"}}}]});
        let request = responses_body(&chat).unwrap();
        assert_eq!(request["instructions"], "Be brief.");
        assert_eq!(request["stream"], true);
        assert_eq!(request["store"], false);
        assert!(request.get("max_tokens").is_none() && request.get("messages").is_none());
        assert_eq!(
            request["input"],
            json!([
            {"role": "user", "content": "read a"},
            {"type": "function_call", "call_id": "c1", "name": "file_read", "arguments": "{\"path\":\"a\"}", "namespace": "enzimos"},
            {"type": "function_call_output", "call_id": "c1", "output": "{\"ok\":true}"}])
        );
        assert_eq!(request["tools"][0]["type"], "namespace");
        assert_eq!(
            request["tools"][0]["tools"][0],
            json!({"type": "function", "name": "file_read", "description": "Read", "parameters": {"type": "object"}})
        );
    }

    #[test]
    fn plan_requests_keep_screenshot_images_in_the_model_context() {
        let image = "data:image/jpeg;base64,AA==";
        let chat = |url: &str| {
            json!({"model": "gpt-5", "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Visual result"},
                    {"type": "image_url", "image_url": {"url": url}},
                ]}
            ]})
        };
        assert_eq!(
            responses_body(&chat(image)).unwrap()["input"][0]["content"],
            json!([
                {"type": "input_text", "text": "Visual result"},
                {"type": "input_image", "image_url": image, "detail": "auto"}
            ])
        );
        assert!(responses_body(&chat("https://example.org/capture.jpg")).is_err());
    }

    #[test]
    fn plan_events_become_chat_chunks() {
        let mut translator = Translator::default();
        let events = [
            json!({"type": "response.created"}),
            json!({"type": "response.reasoning_summary_text.delta", "delta": "hm"}),
            json!({"type": "response.output_text.delta", "delta": "Hi"}),
            json!({"type": "response.output_item.done", "item": {"type": "function_call", "call_id": "c9", "name": "files_list", "namespace": "enzimos", "arguments": "{}"}}),
            json!({"type": "response.completed"}),
        ];
        let stream = events
            .iter()
            .map(|e| format!("event: x\ndata: {e}\n\n"))
            .collect::<String>();
        let (first, rest) = stream.as_bytes().split_at(40);
        let mut out = translator.feed(first).unwrap();
        out.extend(translator.feed(rest).unwrap());
        let out = String::from_utf8(out).unwrap();
        let chunks = out
            .split("\n\n")
            .filter(|c| !c.is_empty())
            .map(|c| c.trim_start_matches("data: "))
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 4, "{out}");
        let delta = |i: usize| {
            serde_json::from_str::<Value>(chunks[i]).unwrap()["choices"][0]["delta"].clone()
        };
        assert_eq!(delta(0), json!({"reasoning_content": "hm"}));
        assert_eq!(delta(1), json!({"content": "Hi"}));
        assert_eq!(
            delta(2)["tool_calls"][0],
            json!({"index": 0, "id": "c9", "type": "function", "function": {"name": "files_list", "arguments": "{}"}})
        );
        assert_eq!(chunks[3], "[DONE]");
        assert!(translator.done);
        let mut failing = Translator::default();
        let limit = format!(
            "data: {}\n",
            json!({"type": "response.failed", "response": {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}})
        );
        assert!(
            failing
                .feed(limit.as_bytes())
                .unwrap_err()
                .contains("usage limit")
        );
    }

    #[test]
    fn base64url_round_trips() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            &[0xff, 0xfe, 0x00, 0x10],
        ] {
            assert_eq!(unbase64url(&base64url(data)).unwrap(), data);
        }
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
    }
}
