// SPDX-License-Identifier: MIT
//! Outgoing HTTP/1.1 to a provider: one request per connection, TLS unless
//! the endpoint is a loopback HTTP address, responses read incrementally.
use crate::{Failure, Stream, http, parse_url, step, tls_config};
use std::collections::HashMap;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Where requests go: an `https://` URL, or `http://` on loopback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    /// Path prefix without a trailing slash.
    pub(crate) path: String,
}

impl Endpoint {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let url = parse_url(value)?;
        let loopback = ["127.0.0.1", "::1", "localhost"].contains(&url.host.as_str());
        if url.scheme != "https" && !(url.scheme == "http" && loopback) {
            return Err("remote providers require HTTPS".into());
        }
        let tls = url.scheme == "https";
        Ok(Self {
            port: url.port.unwrap_or(if tls { 443 } else { 80 }),
            host: url.host,
            tls,
            path: url.path.trim_end_matches('/').to_owned(),
        })
    }

    pub(crate) async fn connect(&self) -> Result<Box<dyn Stream>, Failure> {
        let tcp = step(15, TcpStream::connect((self.host.as_str(), self.port))).await?;
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| Failure::Unavailable)?;
        Ok(Box::new(
            step(
                15,
                tokio_rustls::TlsConnector::from(tls_config()?).connect(name, tcp),
            )
            .await?,
        ))
    }

    /// One request; `body` is sent with `content_type` when given.
    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<(&str, &[u8])>,
    ) -> Vec<u8> {
        let mut head = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.path,
            http::host_header(&self.host, self.port, self.tls)
        );
        for (key, value) in headers {
            head.push_str(key);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        if let Some((content_type, data)) = body {
            head.push_str("Content-Type: ");
            head.push_str(content_type);
            head.push_str("\r\nContent-Length: ");
            head.push_str(&data.len().to_string());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        if let Some((_, data)) = body {
            bytes.extend_from_slice(data);
        }
        bytes
    }

    /// Send one request and read the whole response (at most 1 MiB, 30 s).
    pub(crate) async fn fetch(&self, request: &[u8]) -> Result<(u16, Vec<u8>), Failure> {
        let mut stream = self.connect().await?;
        step(30, async {
            stream.write_all(request).await?;
            stream.flush().await
        })
        .await?;
        read_response(&mut stream).await
    }
}

pub(crate) async fn read_response(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<(u16, Vec<u8>), Failure> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut response = Response::default();
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 16384];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| Failure::Unavailable)?;
            if n == 0 {
                if response.chunked || response.remaining.is_some_and(|left| left != 0) {
                    return Err(Failure::Unavailable);
                }
                break;
            }
            response
                .push(&chunk[..n], &mut body)
                .map_err(Failure::Bad)?;
            if body.len() > 1024 * 1024 {
                return Err(Failure::Bad("provider response exceeds bound".into()));
            }
            if response.finished() {
                break;
            }
        }
        Ok((response.status.ok_or(Failure::Unavailable)?, body))
    })
    .await
    .map_err(|_| Failure::Unavailable)?
}

/// A response read as it arrives: the head, then the body with chunked
/// transfer coding removed.
#[derive(Default)]
pub(crate) struct Response {
    head: Vec<u8>,
    pub(crate) status: Option<u16>,
    pub(crate) headers: HashMap<String, String>,
    chunked: bool,
    remaining: Option<usize>,
    state: Chunk,
    size: Vec<u8>,
}

#[derive(Default)]
enum Chunk {
    #[default]
    Size,
    Data(usize),
    /// The CRLF after a chunk; the count is how many of its bytes are left.
    End(usize),
    Done,
}

impl Response {
    /// Feed received bytes; body bytes are appended to `body`.
    pub(crate) fn push(&mut self, mut input: &[u8], body: &mut Vec<u8>) -> Result<(), String> {
        if self.status.is_none() {
            self.head.extend_from_slice(input);
            let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.head.len() > http::HEAD_LIMIT {
                    return Err("provider response head exceeds limit".into());
                }
                return Ok(());
            };
            if end > http::HEAD_LIMIT {
                return Err("provider response head exceeds limit".into());
            }
            let head = std::mem::take(&mut self.head);
            let text = std::str::from_utf8(&head[..end])
                .map_err(|_| "invalid provider response".to_owned())?;
            let mut lines = text.split("\r\n");
            self.status = Some(
                lines
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .and_then(|code| code.parse().ok())
                    .ok_or("invalid provider response")?,
            );
            for line in lines {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim().to_ascii_lowercase();
                    if key == "content-length" {
                        for value in value.split(',').map(str::trim) {
                            if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                                return Err("invalid provider response length".into());
                            }
                            let length = value
                                .parse()
                                .map_err(|_| "invalid provider response length".to_owned())?;
                            if self
                                .remaining
                                .replace(length)
                                .is_some_and(|previous| previous != length)
                            {
                                return Err("conflicting provider response lengths".into());
                            }
                        }
                    }
                    self.headers.insert(key, value.trim().to_owned());
                }
            }
            self.chunked = self
                .headers
                .get("transfer-encoding")
                .is_some_and(|t| t.eq_ignore_ascii_case("chunked"));
            if self.headers.contains_key("transfer-encoding")
                && (!self.chunked || self.remaining.is_some())
            {
                return Err("unsupported provider response framing".into());
            }
            if self
                .status
                .is_some_and(|status| matches!(status, 204 | 304))
            {
                self.chunked = false;
                self.remaining = Some(0);
            }
            return self.push(&head[end + 4..], body);
        }
        if !self.chunked {
            let take = self
                .remaining
                .map_or(input.len(), |left| left.min(input.len()));
            body.extend_from_slice(&input[..take]);
            if let Some(left) = &mut self.remaining {
                *left -= take;
            }
            return Ok(());
        }
        while !input.is_empty() {
            match self.state {
                Chunk::Size => {
                    let byte = input[0];
                    input = &input[1..];
                    if byte != b'\n' {
                        if self.size.len() > 128 {
                            return Err("invalid provider response framing".into());
                        }
                        self.size.push(byte);
                        continue;
                    }
                    let line = String::from_utf8_lossy(&self.size).into_owned();
                    self.size.clear();
                    let digits = line.split(';').next().unwrap_or_default().trim();
                    let size = usize::from_str_radix(digits, 16)
                        .map_err(|_| "invalid provider response framing".to_owned())?;
                    self.state = if size == 0 {
                        Chunk::Done
                    } else {
                        Chunk::Data(size)
                    };
                }
                Chunk::Data(left) => {
                    let n = left.min(input.len());
                    body.extend_from_slice(&input[..n]);
                    input = &input[n..];
                    self.state = if n == left {
                        Chunk::End(2)
                    } else {
                        Chunk::Data(left - n)
                    };
                }
                Chunk::End(left) => {
                    let n = left.min(input.len());
                    input = &input[n..];
                    self.state = if n == left {
                        Chunk::Size
                    } else {
                        Chunk::End(left - n)
                    };
                }
                Chunk::Done => return Ok(()),
            }
        }
        Ok(())
    }

    /// Whether the framed response body is complete.
    pub(crate) fn finished(&self) -> bool {
        self.remaining == Some(0) || matches!(self.state, Chunk::Done)
    }
}

/// `application/x-www-form-urlencoded` / query encoding of `pairs`.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    let encode = |text: &str| {
        let mut out = String::new();
        for byte in text.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
        out
    };
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Decode one query string into its pairs (`+` is a space).
pub(crate) fn query(text: &str) -> HashMap<String, String> {
    let decode = |text: &str| {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit() =>
                {
                    let hex = |b: u8| char::from(b).to_digit(16).unwrap_or(0) as u8;
                    out.push(hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]));
                    i += 2;
                }
                byte => out.push(byte),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    text.split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, value)| (decode(key), decode(value)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_bodies_decode_across_any_split() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n5\r\nhello\r\n7;x=y\r\n, world\r\n0\r\n\r\n";
        for split in 1..raw.len() {
            let mut response = Response::default();
            let mut body = Vec::new();
            for piece in raw.chunks(split) {
                response.push(piece, &mut body).unwrap();
            }
            assert_eq!(body, b"hello, world", "split {split}");
            assert_eq!(response.status, Some(200));
            assert!(response.finished(), "split {split}");
            assert_eq!(response.headers["content-type"], "text/event-stream");
        }
    }

    #[tokio::test]
    async fn declared_body_length_finishes_without_connection_close() {
        let (mut reader, mut writer) = tokio::io::duplex(256);
        writer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), read_response(&mut reader))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, (200, b"hello".to_vec()));
        for mut response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5, 2\r\n\r\nhello".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi".as_slice(),
        ] {
            assert!(read_response(&mut response).await.is_err());
        }
    }

    #[test]
    fn forms_and_queries_round_trip() {
        let encoded = form(&[
            ("redirect_uri", "http://127.0.0.1:1455/auth/callback"),
            ("scope", "a b"),
        ]);
        assert_eq!(
            encoded,
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback&scope=a%20b"
        );
        let decoded = query(&encoded);
        assert_eq!(
            decoded["redirect_uri"],
            "http://127.0.0.1:1455/auth/callback"
        );
        assert_eq!(decoded["scope"], "a b");
        assert_eq!(query("code=x+y&state=%zz")["state"], "%zz");
    }
}
