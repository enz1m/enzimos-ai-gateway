// SPDX-License-Identifier: MIT
//! Explicit provider routing; no model loading, hardware policy or implicit
//! local-to-cloud fallback. Provider credentials never leave this process.
mod chatgpt;
pub mod http;
pub mod preferences;
mod upstream;

use preferences::Preferences;
use serde_json::{Map, Value, json};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixListener, UnixStream},
};

#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
pub fn credential(path: &str) -> Result<String, String> {
    let refuse = || "private owned credential file required".to_owned();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| refuse())?;
    let m = file.metadata().map_err(|_| refuse())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > 16384
    {
        return Err(refuse());
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|_| refuse())?;
    if raw.len() > 16384 {
        return Err(refuse());
    }
    let token = std::str::from_utf8(&raw)
        .ok()
        .filter(|t| t.is_ascii())
        .map(str::trim)
        .ok_or("invalid credential")?;
    if token.is_empty() || !token.bytes().all(|c| (33..=126).contains(&c)) {
        return Err("invalid credential".into());
    }
    Ok(token.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Local {
        socket: String,
        path: String,
    },
    Remote {
        host: String,
        port: u16,
        tls: bool,
        path: String,
        headers: Vec<(String, String)>,
    },
    /// A ChatGPT plan, through the signed-in account.
    ChatGpt {
        provider: Value,
    },
}

struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

fn parse_url(value: &str) -> Result<Url, String> {
    let invalid = || "invalid provider URL".to_owned();
    if !value.is_ascii() || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid());
    }
    let (scheme, rest) = value.split_once("://").ok_or_else(invalid)?;
    if rest.contains(['?', '#']) {
        return Err(invalid());
    }
    let (authority, path) = rest
        .find('/')
        .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
    if authority.contains('@') {
        return Err(invalid());
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(invalid)?;
        if host.parse::<std::net::Ipv6Addr>().is_err()
            || (!after.is_empty() && !after.starts_with(':'))
        {
            return Err(invalid());
        }
        (
            host.to_owned(),
            after
                .strip_prefix(':')
                .map(|p| p.parse::<u16>().map_err(|_| invalid()))
                .transpose()?,
        )
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p.parse::<u16>().map_err(|_| invalid())?)),
            None => (authority.to_owned(), None),
        }
    };
    if host.is_empty()
        || port == Some(0)
        || (!authority.starts_with('[')
            && (host.len() > 253
                || host.trim_end_matches('.').split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })))
    {
        return Err(invalid());
    }
    Ok(Url {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_owned(),
    })
}

fn local_provider(config: &Value, default: Value) -> Value {
    let is_local = |name: &str| config["providers"][name]["kind"] == "local";
    if default.as_str().is_some_and(is_local) {
        return default;
    }
    config["providers"]
        .as_object()
        .and_then(|providers| providers.keys().find(|name| is_local(name)))
        .map_or(default, |name| json!(name))
}

/// Pick the configured provider; `provider` is removed from the request body.
pub fn route(config: &Value, body: &mut Map<String, Value>, path: &str) -> Result<Target, String> {
    if ![
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/models/warmup",
        "/v1/audio/transcriptions",
    ]
    .contains(&path)
    {
        return Err("unsupported endpoint".into());
    }
    let default = config
        .get("default_provider")
        .cloned()
        .unwrap_or(json!("local"));
    let name = match body.remove("provider") {
        Some(name) => name,
        // Speech has only a local adapter, so it never follows a cloud default.
        None if path == "/v1/audio/transcriptions" => local_provider(config, default),
        None => default,
    };
    let provider = name
        .as_str()
        .and_then(|n| config["providers"].get(n))
        .ok_or("unknown provider")?;
    let kind = provider["kind"].as_str().unwrap_or_default();
    if path == "/v1/models/warmup" && (name != "local" || kind != "local") {
        return Err("model warm-up requires the local provider".into());
    }
    if kind == "chatgpt-login" {
        if provider.get("enabled") != Some(&json!(true)) {
            return Err("cloud provider is disabled".into());
        }
        if path != "/v1/chat/completions" {
            return Err("provider endpoint unsupported".into());
        }
        body.remove("conversation_id");
        return Ok(Target::ChatGpt {
            provider: provider.clone(),
        });
    }
    if kind == "local" {
        if path == "/v1/responses" {
            return Err("local runtime has no Responses adapter".into());
        }
        let socket = provider["socket"]
            .as_str()
            .ok_or("local provider socket required")?;
        return Ok(Target::Local {
            socket: socket.into(),
            path: path.into(),
        });
    }
    body.remove("conversation_id");
    if kind != "openai-compatible" {
        return Err("unsupported provider adapter".into());
    }
    if provider.get("enabled") != Some(&json!(true)) {
        return Err("cloud provider is disabled".into());
    }
    let url = parse_url(provider["base_url"].as_str().unwrap_or_default())?;
    let loopback = ["127.0.0.1", "::1", "localhost"].contains(&url.host.as_str());
    if url.scheme != "https" && !(url.scheme == "http" && loopback) {
        return Err("remote providers require HTTPS".into());
    }
    if url.host.is_empty() {
        return Err("provider host required".into());
    }
    if path == "/v1/audio/transcriptions" {
        return Err("local PCM speech envelope is not a cloud multipart request".into());
    }
    let protocol = if path == "/v1/responses" {
        "responses"
    } else {
        "chat"
    };
    let capabilities = provider
        .get("capabilities")
        .cloned()
        .unwrap_or(json!(["chat"]));
    if !capabilities
        .as_array()
        .is_some_and(|c| c.contains(&json!(protocol)))
    {
        return Err("provider endpoint unsupported".into());
    }
    let mut headers = Vec::new();
    // A misconfigured (non-string) credential path is refused, never sent without auth.
    let file = match provider.get("credential_file") {
        None | Some(Value::Null) => None,
        Some(Value::String(file)) => Some(file.as_str()).filter(|f| !f.is_empty()),
        Some(_) => return Err("invalid credential file".into()),
    };
    if let Some(file) = file {
        headers.push((
            "Authorization".to_owned(),
            format!("Bearer {}", credential(file)?),
        ));
    }
    let tls = url.scheme == "https";
    Ok(Target::Remote {
        port: url.port.unwrap_or(if tls { 443 } else { 80 }),
        path: format!(
            "{}{}",
            url.path.trim_end_matches('/'),
            path.strip_prefix("/v1").unwrap_or(path)
        ),
        host: url.host,
        tls,
        headers,
    })
}

#[derive(Debug)]
enum Failure {
    Bad(String),
    Conflict(String),
    Unavailable,
    Closed,
}

pub struct Gateway {
    config: Mutex<Value>,
    base: Value,
    preferences: Mutex<Preferences>,
    active: AtomicUsize,
    clients: AtomicUsize,
    uid: u32,
    /// The ChatGPT account, kept beside the preferences file.
    accounts: Option<Arc<chatgpt::Accounts>>,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Built once: loading the system roots is blocking file I/O on the only
/// runtime thread. An empty store is reported instead of failing silently.
fn tls_config() -> Result<Arc<tokio_rustls::rustls::ClientConfig>, Failure> {
    static CONFIG: std::sync::OnceLock<Option<Arc<tokio_rustls::rustls::ClientConfig>>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            for certificate in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(certificate);
            }
            if roots.is_empty() {
                eprintln!("enzimos-ai-gateway: no system TLS root certificates; remote providers unavailable");
                return None;
            }
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .ok()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Some(Arc::new(config))
        })
        .clone()
        .ok_or(Failure::Unavailable)
}

/// Resolves when the client has really gone. A half-close (`SHUT_WR`) or
/// trailing bytes after the body are not cancellation; after end of input
/// the socket is polled for a full hangup instead.
#[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
async fn client_gone(reader: &mut tokio::net::unix::OwnedReadHalf) {
    use std::os::fd::AsRawFd;
    let mut discard = [0u8; 4096];
    let mut extra = 0usize;
    loop {
        match reader.read(&mut discard).await {
            Ok(0) => break,
            Ok(n) if extra + n <= 65536 => extra += n,
            _ => return,
        }
    }
    let fd = reader.as_ref().as_raw_fd();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut poll = libc::pollfd {
            fd,
            events: 0,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0
            && poll.revents & (libc::POLLHUP | libc::POLLERR) != 0
        {
            return;
        }
    }
}

/// Bound one network step; a dead route must not hold a job slot for the
/// whole request deadline.
async fn step<T, E>(
    seconds: u64,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, Failure> {
    match tokio::time::timeout(Duration::from_secs(seconds), future).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(Failure::Unavailable),
    }
}

impl Gateway {
    #[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
    pub fn new(config: Value, preferences: Option<&Path>) -> Result<Arc<Self>, String> {
        let base = config.clone();
        let accounts = preferences
            .and_then(Path::parent)
            .map(|directory| Arc::new(chatgpt::Accounts::new(directory.to_path_buf())));
        let validator_config = config.clone();
        let validate: preferences::Validate = Box::new(move |value| {
            if value.len() != 1 || !value.get("default_provider").is_some_and(Value::is_string) {
                return Err("registered provider selection required".into());
            }
            // Only the registration is checked here; credentials and the
            // enabled flag are checked per request and before a commit, so
            // a broken cloud key never stops local AI from starting.
            let name = value["default_provider"].as_str().unwrap_or_default();
            if validator_config["providers"].get(name).is_none() {
                return Err("unknown provider".into());
            }
            Ok(value)
        });
        let defaults = json!({"default_provider": config.get("default_provider").cloned().unwrap_or(json!("local"))});
        let preferences =
            Preferences::new(defaults.as_object().unwrap().clone(), preferences, validate)
                .map_err(|e| format!("{e:?}"))?;
        let mut effective = config;
        for (k, v) in &preferences.value {
            effective[k] = v.clone();
        }
        Ok(Arc::new(Self {
            config: Mutex::new(effective),
            base,
            preferences: Mutex::new(preferences),
            active: AtomicUsize::new(0),
            clients: AtomicUsize::new(0),
            uid: unsafe { libc::getuid() },
            accounts,
        }))
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // Back off on descriptor exhaustion instead of spinning.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            };
            let gateway = self.clone();
            tokio::spawn(async move { gateway.client(stream).await });
        }
    }

    async fn client(&self, stream: UnixStream) {
        let clients = self.clients.fetch_add(1, Ordering::SeqCst) + 1;
        let uid = stream.peer_cred().map(|c| c.uid()).ok();
        let (mut reader, mut writer) = stream.into_split();
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = async {
            if clients > 16 {
                return Ok(Some((429, json!({"error": "AI gateway busy"}))));
            }
            if uid != Some(self.uid) {
                return Ok(Some((403, json!({"error": "peer UID refused"}))));
            }
            self.handle(&mut reader, &mut writer, &started).await
        }
        .await;
        let response = match result {
            Ok(Some(response)) => Some(response),
            Ok(None) | Err(Failure::Closed) => None,
            Err(Failure::Conflict(message)) => Some((409, json!({"error": message}))),
            Err(Failure::Bad(message)) => Some((400, json!({"error": message}))),
            Err(Failure::Unavailable) => {
                Some((503, json!({"error": "selected provider unavailable"})))
            }
        };
        if let Some((status, body)) = response.filter(|_| !started.load(Ordering::SeqCst)) {
            let _ = http::reply(&mut writer, status, &body).await;
        }
        let _ = writer.shutdown().await;
        self.clients.fetch_sub(1, Ordering::SeqCst);
    }

    async fn handle(
        &self,
        reader: &mut tokio::net::unix::OwnedReadHalf,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        started: &Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<(u16, Value)>, Failure> {
        let request = http::read_head(reader).await.map_err(|e| {
            if e == "connection closed" {
                Failure::Closed
            } else {
                Failure::Bad(e)
            }
        })?;
        let (path, query) = request
            .path
            .split_once('?')
            .unwrap_or((request.path.as_str(), ""));
        if request.method == "GET" {
            let config = self.config.lock().unwrap().clone();
            return match path {
                "/v1/accounts/chatgpt" => Ok(Some((200, self.accounts()?.status()))),
                "/v1/models" => {
                    let name = upstream::query(query).remove("provider");
                    self.models(&config, name)
                        .await
                        .map(|list| Some((200, list)))
                }
                "/v1/preferences" => Ok(Some((200, self.preferences.lock().unwrap().snapshot()))),
                "/health" => Ok(Some((
                    200,
                    json!({"ready": true, "default_provider": config.get("default_provider").cloned().unwrap_or(json!("local"))}),
                ))),
                "/v1/providers" => {
                    let providers = config["providers"].as_object().map(|p| p.iter().map(|(id, p)| {
                        let local = p["kind"] == "local";
                        json!({"id": id, "kind": p["kind"], "enabled": p.get("enabled").cloned().unwrap_or(json!(local)), "capabilities": p.get("capabilities").cloned().unwrap_or(json!([]))})
                    }).collect::<Vec<_>>()).unwrap_or_default();
                    Ok(Some((200, json!({"providers": providers}))))
                }
                _ => Err(Failure::Bad("unsupported request".into())),
            };
        }
        if request.method != "POST" {
            return Err(Failure::Bad("unsupported request".into()));
        }
        let limit = if matches!(path, "/v1/preferences" | "/v1/models/warmup") {
            4096
        } else {
            3 * 1024 * 1024
        };
        let body = http::read_body(reader, &request, limit)
            .await
            .map_err(|e| {
                if e == "connection closed" {
                    Failure::Closed
                } else {
                    Failure::Bad(e)
                }
            })?;
        let mut body = body.as_object().cloned().unwrap_or_default();
        if let Some(action) = path.strip_prefix("/v1/accounts/chatgpt/") {
            let config = self.config.lock().unwrap().clone();
            let provider = body
                .get("provider")
                .and_then(Value::as_str)
                .and_then(|name| config["providers"].get(name))
                .filter(|p| p["kind"] == "chatgpt-login")
                .cloned()
                .ok_or_else(|| Failure::Bad("ChatGPT provider required".into()))?;
            let accounts = self.accounts()?;
            let result = match action {
                "login" => accounts.begin(&provider).await,
                "logout" => accounts.sign_out(&provider).await,
                _ => return Err(Failure::Bad("unsupported request".into())),
            };
            return result.map(|value| Some((200, value))).map_err(Failure::Bad);
        }
        if path == "/v1/preferences" {
            if self.active.load(Ordering::SeqCst) > 0 {
                return Ok(Some((
                    409,
                    json!({"error": "provider jobs active; retry after completion"}),
                )));
            }
            if let Some(name) = body
                .get("preferences")
                .and_then(|p| p.get("default_provider"))
            {
                let mut probe = Map::new();
                probe.insert("provider".into(), name.clone());
                route(&self.base, &mut probe, "/v1/chat/completions").map_err(Failure::Bad)?;
            }
            let mut preferences = self.preferences.lock().unwrap();
            let snapshot = preferences.commit(&body).map_err(|e| match e {
                preferences::Error::Conflict(m) => Failure::Conflict(m),
                preferences::Error::Invalid(m) => Failure::Bad(m),
            })?;
            let mut config = self.base.clone();
            for (k, v) in &preferences.value {
                config[k] = v.clone();
            }
            *self.config.lock().unwrap() = config;
            return Ok(Some((200, snapshot)));
        }
        if self.active.load(Ordering::SeqCst) >= 2 {
            return Ok(Some((429, json!({"error": "AI gateway busy"}))));
        }
        let config = self.config.lock().unwrap().clone();
        let target = route(&config, &mut body, path).map_err(Failure::Bad)?;
        self.active.fetch_add(1, Ordering::SeqCst);
        // The client disconnecting cancels the provider request.
        let body = Value::Object(body);
        let result = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(1800), self.proxy(&target, &body, writer, started)) => result.map_err(|_| Failure::Unavailable).and_then(|r| r),
            () = client_gone(reader) => Err(Failure::Closed),
        };
        self.active.fetch_sub(1, Ordering::SeqCst);
        result.map(|()| None)
    }

    fn accounts(&self) -> Result<&Arc<chatgpt::Accounts>, Failure> {
        self.accounts.as_ref().ok_or_else(|| {
            Failure::Bad("account sign-in needs the --preferences state folder".into())
        })
    }

    /// The models one provider (default: the selected one) offers, as
    /// `/v1/models` lists them.
    async fn models(&self, config: &Value, name: Option<String>) -> Result<Value, Failure> {
        let name = name
            .or_else(|| config["default_provider"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "local".into());
        let provider = config["providers"]
            .get(&name)
            .ok_or_else(|| Failure::Bad("unknown provider".into()))?;
        let read = |(status, body): (u16, Vec<u8>)| {
            if status != 200 {
                return Err(Failure::Unavailable);
            }
            serde_json::from_slice::<Value>(&body).map_err(|_| Failure::Unavailable)
        };
        match provider["kind"].as_str().unwrap_or_default() {
            "chatgpt-login" => self.accounts()?.models(provider).await,
            "local" => {
                let socket = provider["socket"]
                    .as_str()
                    .ok_or_else(|| Failure::Bad("local provider socket required".into()))?;
                let mut stream = step(15, UnixStream::connect(socket)).await?;
                step(
                    15,
                    stream.write_all(
                        b"GET /v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    ),
                )
                .await?;
                read(upstream::read_response(&mut stream).await?)
            }
            "openai-compatible" => {
                if provider.get("enabled") != Some(&json!(true)) {
                    return Err(Failure::Bad("cloud provider is disabled".into()));
                }
                let endpoint =
                    upstream::Endpoint::parse(provider["base_url"].as_str().unwrap_or_default())
                        .map_err(Failure::Bad)?;
                let mut headers = Vec::new();
                if let Some(file) = provider["credential_file"]
                    .as_str()
                    .filter(|f| !f.is_empty())
                {
                    headers.push((
                        "Authorization".to_owned(),
                        format!("Bearer {}", credential(file).map_err(Failure::Bad)?),
                    ));
                }
                read(
                    endpoint
                        .fetch(&endpoint.request("GET", "/models", &headers, None))
                        .await?,
                )
            }
            _ => Err(Failure::Bad("unsupported provider adapter".into())),
        }
    }

    async fn proxy(
        &self,
        target: &Target,
        body: &Value,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        started: &Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), Failure> {
        // Local model loads can take minutes before the first byte; a remote
        // provider that goes silent this long is a dead route.
        let (mut upstream, request, idle): (Box<dyn Stream>, Vec<u8>, u64) = match target {
            Target::ChatGpt { provider } => {
                return self
                    .accounts()?
                    .relay(provider, body, writer, started)
                    .await;
            }
            Target::Local { socket, path } => {
                let stream = step(15, UnixStream::connect(socket)).await?;
                (
                    Box::new(stream),
                    http::post(path, "localhost", &[], body),
                    600,
                )
            }
            Target::Remote {
                host,
                port,
                tls,
                path,
                headers,
            } => {
                let tcp = step(15, TcpStream::connect((host.as_str(), *port))).await?;
                let stream: Box<dyn Stream> = if *tls {
                    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|_| Failure::Unavailable)?;
                    Box::new(
                        step(
                            15,
                            tokio_rustls::TlsConnector::from(tls_config()?).connect(name, tcp),
                        )
                        .await?,
                    )
                } else {
                    Box::new(tcp)
                };
                (
                    stream,
                    http::post(path, &http::host_header(host, *port, *tls), headers, body),
                    180,
                )
            }
        };
        step(30, async {
            upstream.write_all(&request).await?;
            upstream.flush().await
        })
        .await?;
        let mut total = 0usize;
        let mut chunk = vec![0u8; 65536];
        loop {
            let n = step(idle, upstream.read(&mut chunk)).await?;
            if n == 0 {
                return Ok(());
            }
            total += n;
            if total > 4 * 1024 * 1024 {
                return Err(Failure::Bad("provider output exceeds bound".into()));
            }
            started.store(true, Ordering::SeqCst);
            writer
                .write_all(&chunk[..n])
                .await
                .map_err(|_| Failure::Closed)?;
        }
    }
}

/// Bind a new socket inside a private owned directory.
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid, umask).")]
pub fn bind(path: &Path) -> Result<UnixListener, String> {
    let parent = path.parent().ok_or("socket directory required")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode_0700()
        .create(parent)
        .map_err(|_| "socket directory unavailable")?;
    let m = std::fs::symlink_metadata(parent).map_err(|_| "socket directory unavailable")?;
    if path.exists() || !m.is_dir() || m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0
    {
        return Err("new socket in private owned directory required".into());
    }
    unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(path).map_err(|_| "socket unavailable")?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|_| "socket unavailable")?;
    Ok(listener)
}

trait Mode0700 {
    fn mode_0700(&mut self) -> &mut Self;
}
impl Mode0700 for std::fs::DirBuilder {
    fn mode_0700(&mut self) -> &mut Self {
        std::os::unix::fs::DirBuilderExt::mode(self, 0o700)
    }
}

pub fn socket_path(value: &str) -> PathBuf {
    PathBuf::from(value)
}

#[cfg(test)]
mod tests;
