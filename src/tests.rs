// SPDX-License-Identifier: MIT
use super::*;
use crate::preferences::tests::private_dir;
use std::os::unix::fs::PermissionsExt;
use tokio::net::TcpListener;

fn config(local: &str, remote: &str) -> Value {
    json!({"default_provider": "local", "providers": {
        "local": {"kind": "local", "socket": local},
        "cloud": {"kind": "openai-compatible", "enabled": true, "base_url": remote, "capabilities": ["chat", "responses"]},
        "off": {"kind": "openai-compatible", "enabled": false, "base_url": "https://example.com/v1"},
        "login": {"kind": "chatgpt-login"}}})
}
fn body(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn local_default_and_explicit_cloud_without_fallback() {
    let c = config("/run/x.sock", "https://api.example.com/v1/");
    let mut b = body(json!({"messages": [], "conversation_id": "c"}));
    assert_eq!(
        route(&c, &mut b, "/v1/chat/completions").unwrap(),
        Target::Local {
            socket: "/run/x.sock".into(),
            path: "/v1/chat/completions".into()
        }
    );
    let mut b = body(json!({"provider": "cloud", "conversation_id": "c"}));
    let Target::Remote {
        host,
        port,
        tls,
        path,
        headers,
    } = route(&c, &mut b, "/v1/responses").unwrap()
    else {
        panic!()
    };
    assert_eq!(
        (host.as_str(), port, tls, path.as_str(), headers.len()),
        ("api.example.com", 443, true, "/v1/responses", 0)
    );
    assert!(!b.contains_key("provider") && !b.contains_key("conversation_id"));
}

#[test]
fn speech_stays_local_under_a_cloud_default() {
    let mut c = config("/run/x.sock", "https://api.example.com/v1/");
    c["default_provider"] = json!("cloud");
    assert_eq!(
        route(&c, &mut body(json!({})), "/v1/audio/transcriptions").unwrap(),
        Target::Local {
            socket: "/run/x.sock".into(),
            path: "/v1/audio/transcriptions".into()
        }
    );
    assert!(matches!(
        route(&c, &mut body(json!({})), "/v1/chat/completions").unwrap(),
        Target::Remote { .. }
    ));
    assert!(
        route(
            &c,
            &mut body(json!({"provider": "cloud"})),
            "/v1/audio/transcriptions"
        )
        .is_err()
    );
}

#[test]
fn refusals_for_http_disabled_login_and_protocols() {
    let c = config("/run/x.sock", "http://api.example.com/v1");
    let refuse =
        |name: &str, path: &str| route(&c, &mut body(json!({"provider": name})), path).unwrap_err();
    assert_eq!(
        refuse("cloud", "/v1/chat/completions"),
        "remote providers require HTTPS"
    );
    assert_eq!(
        refuse("off", "/v1/chat/completions"),
        "cloud provider is disabled"
    );
    assert_eq!(
        refuse("login", "/v1/chat/completions"),
        "cloud provider is disabled"
    );
    assert_eq!(
        refuse("local", "/v1/responses"),
        "local runtime has no Responses adapter"
    );
    assert_eq!(refuse("nobody", "/v1/chat/completions"), "unknown provider");
    assert_eq!(refuse("local", "/v1/other"), "unsupported endpoint");
    let loopback = config("/x", "http://127.0.0.1:9/v1");
    assert!(
        route(
            &loopback,
            &mut body(json!({"provider": "cloud"})),
            "/v1/chat/completions"
        )
        .is_ok()
    );
    for url in [
        "https://example.com/v1\r\nX: injected",
        "https://example.com/a b",
        "https://[::1]junk/v1",
        "https://[invalid]/v1",
        "https://:443/v1",
        "https://bad..host/v1",
    ] {
        assert!(
            route(
                &config("/x", url),
                &mut body(json!({"provider":"cloud"})),
                "/v1/chat/completions"
            )
            .is_err(),
            "{url:?}"
        );
    }
    assert!(
        route(
            &config("/x", "http://[::1]:9/v1"),
            &mut body(json!({"provider":"cloud"})),
            "/v1/chat/completions"
        )
        .is_ok()
    );
    let userinfo = config("/x", "https://user:pw@example.com/v1");
    assert_eq!(
        route(
            &userinfo,
            &mut body(json!({"provider": "cloud"})),
            "/v1/chat/completions"
        )
        .unwrap_err(),
        "invalid provider URL"
    );
}

#[test]
fn credentials_must_be_private_regular_files() {
    let dir = private_dir();
    let path = dir.path().join("token");
    std::fs::write(&path, "sk-test\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(credential(path.to_str().unwrap()).unwrap(), "sk-test");
    let mut c = config("/x", "https://api.example.com/v1");
    c["providers"]["cloud"]["credential_file"] = json!(path.to_str().unwrap());
    let Target::Remote { headers, .. } = route(
        &c,
        &mut body(json!({"provider": "cloud"})),
        "/v1/chat/completions",
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(
        headers,
        [("Authorization".to_owned(), "Bearer sk-test".to_owned())]
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(credential(path.to_str().unwrap()).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&path, dir.path().join("link")).unwrap();
    assert!(credential(dir.path().join("link").to_str().unwrap()).is_err());
    std::fs::write(&path, "bad token\n").unwrap();
    assert!(credential(path.to_str().unwrap()).is_err());
}

async fn request(socket: &Path, raw: String) -> String {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    out
}
fn post(path: &str, body: &Value) -> String {
    let data = body.to_string();
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{data}",
        data.len()
    )
}

/// A fake local runtime: records the request and streams two SSE events.
async fn fake_local(path: PathBuf) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = UnixListener::bind(&path).unwrap();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let n = s.read(&mut buf).await.unwrap();
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\ndata: two\n\n").await;
        }
    });
    seen
}

async fn start(config: Value, dir: &Path, preferences: bool) -> PathBuf {
    let socket = dir.join("run/gateway.sock");
    let prefs = preferences.then(|| dir.join("state.json"));
    let gateway = Gateway::new(config, prefs.as_deref()).unwrap();
    let listener = bind(&socket).unwrap();
    tokio::spawn(gateway.serve(listener));
    socket
}

#[tokio::test(flavor = "current_thread")]
async fn stream_relay_strips_routing_fields() {
    let dir = private_dir();
    let local = dir.path().join("local.sock");
    let seen = fake_local(local.clone()).await;
    let socket = start(
        config(local.to_str().unwrap(), "https://x.example/v1"),
        dir.path(),
        false,
    )
    .await;
    let out = request(
        &socket,
        post(
            "/v1/chat/completions",
            &json!({"provider": "local", "messages": [], "stream": true}),
        ),
    )
    .await;
    assert!(
        out.starts_with("HTTP/1.1 200 OK") && out.contains("data: two"),
        "{out}"
    );
    let forwarded = seen.lock().unwrap()[0].clone();
    assert!(
        forwarded.starts_with("POST /v1/chat/completions HTTP/1.1")
            && !forwarded.contains("provider")
    );
    let health = request(&socket, "GET /health HTTP/1.1\r\n\r\n".into()).await;
    assert!(health.contains("\"default_provider\":\"local\""));
}

#[tokio::test(flavor = "current_thread")]
async fn failed_local_never_reaches_the_cloud() {
    let dir = private_dir();
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = remote.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let _ = remote.accept().await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let socket = start(
        config(
            dir.path().join("missing.sock").to_str().unwrap(),
            &format!("http://127.0.0.1:{port}/v1"),
        ),
        dir.path(),
        false,
    )
    .await;
    let out = request(
        &socket,
        post("/v1/chat/completions", &json!({"messages": []})),
    )
    .await;
    assert!(
        out.starts_with("HTTP/1.1 503") && out.contains("selected provider unavailable"),
        "{out}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_requests_are_refused() {
    let dir = private_dir();
    let socket = start(config("/x", "https://x.example/v1"), dir.path(), false).await;
    let dup = request(
        &socket,
        "GET /health HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n".into(),
    )
    .await;
    assert!(dup.starts_with("HTTP/1.1 400") && dup.contains("duplicate header"));
    let chunked = request(
        &socket,
        "POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
    )
    .await;
    assert!(chunked.starts_with("HTTP/1.1 400"));
    let array = request(&socket, post("/v1/chat/completions", &json!([1]))).await;
    assert!(array.contains("JSON object required"));
}

#[tokio::test(flavor = "current_thread")]
async fn live_preference_commit_is_revision_bound() {
    let dir = private_dir();
    let socket = start(config("/x", "https://x.example/v1"), dir.path(), true).await;
    let snapshot = request(&socket, "GET /v1/preferences HTTP/1.1\r\n\r\n".into()).await;
    let snapshot: Value = serde_json::from_str(snapshot.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let change = |revision: &Value, provider: &str| {
        post(
            "/v1/preferences",
            &json!({"schema_version": 1, "revision": revision, "preferences": {"default_provider": provider}}),
        )
    };
    let bad = request(&socket, change(&snapshot["revision"], "off")).await;
    assert!(
        bad.starts_with("HTTP/1.1 400") && bad.contains("cloud provider is disabled"),
        "{bad}"
    );
    let ok = request(&socket, change(&snapshot["revision"], "cloud")).await;
    assert!(
        ok.starts_with("HTTP/1.1 200") && ok.contains("\"default_provider\":\"cloud\""),
        "{ok}"
    );
    let stale = request(&socket, change(&snapshot["revision"], "local")).await;
    assert!(stale.starts_with("HTTP/1.1 409"));
    let health = request(&socket, "GET /health HTTP/1.1\r\n\r\n".into()).await;
    assert!(health.contains("\"default_provider\":\"cloud\""));
}

#[tokio::test(flavor = "current_thread")]
async fn half_closed_client_still_gets_the_stream() {
    let dir = private_dir();
    let local = dir.path().join("local.sock");
    fake_local(local.clone()).await;
    let socket = start(
        config(local.to_str().unwrap(), "https://x.example/v1"),
        dir.path(),
        false,
    )
    .await;
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    stream
        .write_all(post("/v1/chat/completions", &json!({"messages": []})).as_bytes())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    assert!(out.contains("data: two"), "{out}");
}

#[tokio::test(flavor = "current_thread")]
async fn stale_stored_provider_falls_back_to_default() {
    let dir = private_dir();
    let state = dir.path().join("state.json");
    std::fs::write(&state, br#"{"default_provider":"removed"}"#).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut c = config("/x", "https://x.example/v1");
    c["providers"]["cloud"]["credential_file"] =
        json!(dir.path().join("absent-key").to_str().unwrap());
    let socket = start(c, dir.path(), true).await;
    let health = request(&socket, "GET /health HTTP/1.1\r\n\r\n".into()).await;
    assert!(
        health.contains("\"default_provider\":\"local\""),
        "{health}"
    );
}

#[test]
fn host_header_keeps_port_and_brackets() {
    assert_eq!(
        http::host_header("api.example.com", 443, true),
        "api.example.com"
    );
    assert_eq!(
        http::host_header("api.example.com", 8443, true),
        "api.example.com:8443"
    );
    assert_eq!(http::host_header("::1", 11434, false), "[::1]:11434");
}

/// One recorded request to a fake HTTP server: method, path, headers, body.
type Seen = Arc<
    Mutex<
        Vec<(
            String,
            String,
            std::collections::HashMap<String, String>,
            String,
        )>,
    >,
>;

/// A loopback HTTP server answering each request with `answer`'s raw response.
async fn fake_http(
    answer: impl Fn(&str, &str, &str) -> String + Send + Sync + 'static,
) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let request = http::read_head(&mut s).await.unwrap();
            let length = request
                .headers
                .get("content-length")
                .map_or(0, |l| l.parse::<usize>().unwrap());
            let mut body = request.rest.clone();
            body.resize(length, 0);
            s.read_exact(&mut body[request.rest.len()..]).await.unwrap();
            let body = String::from_utf8(body).unwrap();
            let reply = answer(&request.method, &request.path, &body);
            log.lock()
                .unwrap()
                .push((request.method, request.path, request.headers, body));
            let _ = s.write_all(reply.as_bytes()).await;
        }
    });
    (base, seen)
}

fn json_reply(value: &Value) -> String {
    let data = value.to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}",
        data.len()
    )
}

fn unsigned_jwt(claims: &Value) -> String {
    let part = |v: &Value| chatgpt_tests::encode(v.to_string().as_bytes());
    format!("{}.{}.sig", part(&json!({"alg": "RS256"})), part(claims))
}

mod chatgpt_tests {
    pub(super) fn encode(data: &[u8]) -> String {
        crate::chatgpt::tests_support::base64url(data)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn chatgpt_sign_in_relay_refresh_and_sign_out() {
    let dir = private_dir();
    let nonce = Arc::new(Mutex::new(String::new()));
    let issued = nonce.clone();
    let (auth, auth_seen) = {
        let base = Arc::new(Mutex::new(String::new()));
        let own = base.clone();
        let (url, seen) = fake_http(move |method, path, body| {
            let base = own.lock().unwrap().clone();
            match (method, path) {
                ("GET", "/.well-known/openid-configuration") => json_reply(&json!({"revocation_endpoint": format!("{base}/oauth/revoke")})),
                ("POST", "/oauth/revoke") => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into(),
                ("POST", "/api/accounts/oauth/token") => {
                    let form = upstream::query(body);
                    let fresh = form["grant_type"] == "refresh_token";
                    let id = unsigned_jwt(&json!({"iss": base, "aud": "oaiapp_1", "exp": 4_000_000_000u64, "nonce": *issued.lock().unwrap(), "email": "ann@example.org"}));
                    json_reply(&json!({"access_token": if fresh { "at2" } else { "at1" }, "refresh_token": if fresh { "rt2" } else { "rt1" },
                        "id_token": id, "expires_in": 3600, "token_type": "Bearer",
                        "scope": "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"}))
                }
                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into(),
            }
        })
        .await;
        *base.lock().unwrap() = url.clone();
        (url, seen)
    };
    let (api, api_seen) = fake_http(|_, path, _| {
        if path.ends_with("/models") {
            return json_reply(&json!({"models": [{"slug": "gpt-a", "visibility": "list"}, {"slug": "hidden", "visibility": "hide"}]}));
        }
        let events = [json!({"type": "response.output_text.delta", "delta": "Hi"}), json!({"type": "response.completed"})]
            .iter()
            .map(|e| format!("data: {e}\n\n"))
            .collect::<String>();
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{events}\r\n0\r\n\r\n", events.len())
    })
    .await;
    let config = json!({"default_provider": "chatgpt", "providers": {"chatgpt": {"kind": "chatgpt-login", "enabled": true,
        "auth_url": auth, "api_url": format!("{api}/v1")}}});
    let socket = start(config, dir.path(), true).await;
    let reply =
        |out: &str| serde_json::from_str::<Value>(out.split("\r\n\r\n").nth(1).unwrap()).unwrap();

    let begun = reply(
        &request(
            &socket,
            post(
                "/v1/accounts/chatgpt/login",
                &json!({"provider": "chatgpt"}),
            ),
        )
        .await,
    );
    let url = begun["authorize_url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("{auth}/api/accounts/authorize?")),
        "{url}"
    );
    let pairs = upstream::query(url.split_once('?').unwrap().1);
    assert_eq!(pairs["client_id"], "dynamic_agent_client");
    assert_eq!(pairs["agent_name_hint"], "enzimOS");
    assert_eq!(pairs["resource"], "https://api.openai.com/v1");
    assert!(pairs["scope"].contains("chatgpt.tokens.use.direct"));
    *nonce.lock().unwrap() = pairs["nonce"].clone();
    // The browser returns to the loopback callback.
    let callback = pairs["redirect_uri"]
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    let mut browser = tokio::net::TcpStream::connect(callback.0).await.unwrap();
    let back = format!(
        "GET /{}?code=c0de&state={}&client_id=oaiapp_1 HTTP/1.1\r\nHost: x\r\n\r\n",
        callback.1, pairs["state"]
    );
    browser.write_all(back.as_bytes()).await.unwrap();
    let mut page = String::new();
    browser.read_to_string(&mut page).await.unwrap();
    assert!(page.contains("Signed in"), "{page}");
    let mut status = Value::Null;
    for _ in 0..100 {
        status = reply(&request(&socket, "GET /v1/accounts/chatgpt HTTP/1.1\r\n\r\n".into()).await);
        if status["signed_in"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        (&status["signed_in"], &status["email"]),
        (&json!(true), &json!("ann@example.org")),
        "{status}"
    );
    let exchange = auth_seen
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.1 == "/api/accounts/oauth/token")
        .unwrap()
        .3
        .clone();
    let form = upstream::query(&exchange);
    let challenge = chatgpt_tests::encode(
        ring::digest::digest(&ring::digest::SHA256, form["code_verifier"].as_bytes()).as_ref(),
    );
    assert_eq!(
        (form["client_id"].as_str(), form["code"].as_str(), challenge),
        ("oaiapp_1", "c0de", pairs["code_challenge"].clone())
    );
    let account = dir.path().join("chatgpt-account.json");
    assert_eq!(
        std::fs::metadata(&account).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let chat = json!({"provider": "chatgpt", "model": "gpt-a", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let out = request(&socket, post("/v1/chat/completions", &chat)).await;
    assert!(
        out.contains("\"content\":\"Hi\"") && out.ends_with("data: [DONE]\n\n"),
        "{out}"
    );
    let sent = api_seen.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        (sent.1.as_str(), sent.2["authorization"].as_str()),
        ("/v1/responses", "Bearer at1")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&sent.3).unwrap()["store"],
        false
    );

    // An expiring access token is refreshed, and the rotated refresh token kept.
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&account).unwrap()).unwrap();
    saved["expires_at"] = json!(0);
    std::fs::write(&account, saved.to_string()).unwrap();
    let models = reply(&request(&socket, "GET /v1/models HTTP/1.1\r\n\r\n".into()).await);
    assert_eq!(models["data"], json!([{"id": "gpt-a", "object": "model"}]));
    assert_eq!(
        api_seen.lock().unwrap().last().unwrap().2["authorization"],
        "Bearer at2"
    );
    let saved: Value = serde_json::from_slice(&std::fs::read(&account).unwrap()).unwrap();
    assert_eq!(saved["refresh_token"], "rt2");

    let out = reply(
        &request(
            &socket,
            post(
                "/v1/accounts/chatgpt/logout",
                &json!({"provider": "chatgpt"}),
            ),
        )
        .await,
    );
    assert_eq!(out, json!({"signed_in": false, "revoked": true}));
    let revoked = auth_seen
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.1 == "/oauth/revoke")
        .unwrap()
        .3
        .clone();
    assert_eq!(upstream::query(&revoked)["token"], "rt2");
    let out = request(&socket, post("/v1/chat/completions", &chat)).await;
    assert!(out.contains("sign in to ChatGPT"), "{out}");
}
