use super::socket_stream::SocketStream;

use crate::types::{HttpError, HttpProgress, HttpRequest, HttpResponse, NetworkResponse};
use makepad_live_id::LiveId;
use std::{
    collections::HashMap,
    io,
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

pub struct LinuxHttpSocket;

impl LinuxHttpSocket {
    pub fn open(
        request_id: LiveId,
        request: HttpRequest,
        response_sender: Sender<NetworkResponse>,
    ) {
        let cancel_flag = Arc::new(AtomicBool::new(false));
        cancellation_map()
            .lock()
            .unwrap()
            .insert(request_id, cancel_flag.clone());

        std::thread::spawn(move || {
            let metadata_id = request.metadata_id;
            // Redirects are followed here, as the other platforms' HTTP
            // stacks (WinHTTP, NSURLSession) do: Blossom servers answer a
            // blob's GET with a 302 to their storage.
            let mut request = request;
            let mut hops = 0;
            let result = loop {
                match run_http_request(request_id, &request, &response_sender, &cancel_flag) {
                    Ok(None) => break Ok(()),
                    Ok(Some((status, location))) => {
                        hops += 1;
                        if hops > MAX_REDIRECTS {
                            break Err(format!("too many redirects (more than {MAX_REDIRECTS})"));
                        }
                        match redirected(&request, status, &location) {
                            Some(next) => request = next,
                            None => break Err(format!("refused redirect to {location}")),
                        }
                    }
                    Err(e) => break Err(e),
                }
            };

            cancellation_map().lock().unwrap().remove(&request_id);

            if let Err(err) = result {
                let _ = response_sender.send(NetworkResponse::HttpError {
                    request_id,
                    error: HttpError {
                        message: err,
                        metadata_id,
                    },
                });
            }
        });
    }

    pub fn cancel(request_id: LiveId) {
        if let Some(flag) = cancellation_map().lock().unwrap().get(&request_id) {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

fn cancellation_map() -> &'static Mutex<HashMap<LiveId, Arc<AtomicBool>>> {
    static MAP: OnceLock<Mutex<HashMap<LiveId, Arc<AtomicBool>>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn run_http_request(
    request_id: LiveId,
    request: &HttpRequest,
    response_sender: &Sender<NetworkResponse>,
    cancel_flag: &AtomicBool,
) -> Result<Option<(u16, String)>, String> {
    let split = request.split_url();
    let use_tls = match split.proto {
        "http" => false,
        "https" => true,
        other => {
            return Err(format!(
                "unsupported URL scheme for http_request: {other} (expected http or https)"
            ));
        }
    };

    let mut stream =
        SocketStream::connect(split.host, split.port, use_tls, request.ignore_ssl_cert)
            .map_err(|e| format!("connect failed: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    write_request(&mut stream, request, &split, use_tls)
        .map_err(|e| format!("write failed: {e}"))?;

    let max_body = request.max_response_body_bytes;
    let (status_code, headers_string, mut body_prefix, chunked) =
        match read_response_head(&mut stream, cancel_flag, max_body) {
            Ok(response) => response,
            Err(ReadHeadError::BodyLimit) => {
                stream.shutdown();
                return Err(crate::HTTP_BODY_LIMIT_ERROR.to_string());
            }
            Err(ReadHeadError::Io(error)) => return Err(format!("read failed: {error}")),
        };
    if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
        if let Some(location) = header_of(&headers_string, "location").filter(|l| !l.is_empty()) {
            stream.shutdown();
            return Ok(Some((status_code, location.to_owned())));
        }
    }
    let declared = content_length_of(&headers_string);
    if (!matches!(request.method, crate::types::HttpMethod::HEAD) && declared > max_body)
        || body_prefix.len() as u64 > max_body
    {
        stream.shutdown();
        return Err(crate::HTTP_BODY_LIMIT_ERROR.to_string());
    }

    if request.is_streaming {
        let mut streamed = body_prefix.len() as u64;
        if !body_prefix.is_empty() {
            let _ = response_sender.send(NetworkResponse::HttpStreamChunk {
                request_id,
                response: HttpResponse {
                    metadata_id: request.metadata_id,
                    status_code,
                    headers: Default::default(),
                    body: Some(std::mem::take(&mut body_prefix).into()),
                },
            });
        }

        let mut buf = [0u8; 16384];
        loop {
            if cancel_flag.load(Ordering::SeqCst) {
                return Err("request cancelled".to_string());
            }
            let read_len = capped_read_len(max_body, streamed, buf.len());
            match stream.read(&mut buf[..read_len]) {
                Ok(0) => break,
                Ok(n) => {
                    streamed = streamed.saturating_add(n as u64);
                    if streamed > max_body {
                        stream.shutdown();
                        return Err(crate::HTTP_BODY_LIMIT_ERROR.to_string());
                    }
                    let _ = response_sender.send(NetworkResponse::HttpStreamChunk {
                        request_id,
                        response: HttpResponse {
                            metadata_id: request.metadata_id,
                            status_code,
                            headers: Default::default(),
                            body: Some(buf[..n].to_vec().into()),
                        },
                    });
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(format!("stream read failed: {err}")),
            }
        }

        let _ = response_sender.send(NetworkResponse::HttpStreamComplete {
            request_id,
            response: HttpResponse::from_header_string(
                request.metadata_id,
                status_code,
                headers_string,
                None,
            ),
        });
        stream.shutdown();
        return Ok(None);
    }

    let mut body = std::mem::take(&mut body_prefix);
    if max_body != u64::MAX && declared > 0 {
        if let Ok(declared) = usize::try_from(declared) {
            body.reserve_exact(declared.saturating_sub(body.len()));
        }
    }
    let total = declared;
    let mut last_emit = 0usize;
    let emit_progress = |loaded: u64| {
        let _ = response_sender.send(NetworkResponse::HttpProgress {
            request_id,
            progress: HttpProgress { loaded, total },
        });
    };
    emit_progress(body.len() as u64);
    let mut buf = [0u8; 16384];
    loop {
        if cancel_flag.load(Ordering::SeqCst) {
            return Err("request cancelled".to_string());
        }
        let read_len = capped_read_len(max_body, body.len() as u64, buf.len());
        match stream.read(&mut buf[..read_len]) {
            Ok(0) => break,
            Ok(n) => {
                if body.len().saturating_add(n) as u64 > max_body {
                    stream.shutdown();
                    return Err(crate::HTTP_BODY_LIMIT_ERROR.to_string());
                }
                if max_body != u64::MAX && declared == 0 {
                    body.reserve_exact(n);
                }
                body.extend_from_slice(&buf[..n]);
                if body.len().saturating_sub(last_emit) >= 256 * 1024 {
                    last_emit = body.len();
                    emit_progress(body.len() as u64);
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(err) => return Err(format!("read failed: {err}")),
        }
    }
    stream.shutdown();

    if chunked {
        if let Ok(decoded) = decode_chunked_body(&body) {
            body = decoded;
        }
    }

    let _ = response_sender.send(NetworkResponse::HttpResponse {
        request_id,
        response: HttpResponse::from_header_string(
            request.metadata_id,
            status_code,
            headers_string,
            Some(body),
        ),
    });
    Ok(None)
}

fn write_request(
    stream: &mut SocketStream,
    request: &HttpRequest,
    split: &crate::types::SplitUrl<'_>,
    use_tls: bool,
) -> io::Result<()> {
    let path = if split.file.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", split.file)
    };
    let method = request.method.as_str();

    let default_port = if use_tls { "443" } else { "80" };
    let host_header = if split.port == default_port {
        split.host.to_string()
    } else {
        format!("{}:{}", split.host, split.port)
    };

    let mut req = String::new();
    req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str("Connection: close\r\n");

    let mut has_content_length = false;
    for (name, values) in &request.headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        for value in values {
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
    }

    if let Some(body) = &request.body {
        if !has_content_length {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
    }
    req.push_str("\r\n");

    write_all(stream, req.as_bytes())?;
    if let Some(body) = &request.body {
        write_all(stream, body)?;
    }
    stream.flush()
}

enum ReadHeadError {
    Io(io::Error),
    BodyLimit,
}

fn read_response_head(
    stream: &mut SocketStream,
    cancel_flag: &AtomicBool,
    max_body: u64,
) -> Result<(u16, String, Vec<u8>, bool), ReadHeadError> {
    let mut data = Vec::with_capacity(8192);
    let mut buf = [0u8; 4096];
    let mut header_end = None;

    while header_end.is_none() {
        if cancel_flag.load(Ordering::SeqCst) {
            return Err(ReadHeadError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "request cancelled",
            )));
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(ReadHeadError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP headers",
                )));
            }
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                header_end = find_header_end(&data);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(err) => return Err(ReadHeadError::Io(err)),
        }
    }

    let header_end = header_end.unwrap();
    let head = &data[..header_end];
    let body_prefix = &data[header_end..];
    if body_prefix.len() as u64 > max_body {
        return Err(ReadHeadError::BodyLimit);
    }
    let body_prefix = body_prefix.to_vec();
    let head_str = String::from_utf8_lossy(head);

    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or_default();

    let mut headers_string = String::new();
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            headers_string.push_str(name.trim());
            headers_string.push_str(": ");
            headers_string.push_str(value);
            headers_string.push('\n');

            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    Ok((status_code, headers_string, body_prefix, chunked))
}

fn capped_read_len(max_body: u64, received: u64, buffer_len: usize) -> usize {
    let through_first_excess = max_body.saturating_sub(received).saturating_add(1);
    usize::try_from(through_first_excess)
        .unwrap_or(buffer_len)
        .min(buffer_len)
        .max(1)
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn write_all(stream: &mut SocketStream, data: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        match stream.write(&data[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket closed while writing",
                ));
            }
            Ok(n) => offset += n,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// How many redirects one request follows (curl's and browsers' limits are
/// higher; a chain this long is a loop).
const MAX_REDIRECTS: u32 = 5;

/// The first value of a header, by name.
fn header_of<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (n, value) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The request a redirect to `location` makes, as the Fetch standard has it:
/// a 303 (and a 301/302 after a POST) turns into a GET without a body;
/// otherwise the method and body are repeated. Never from https to http, and
/// the credentials (Authorization, Cookie) stay with the host they were meant
/// for. `None`: not a URL we'll follow.
fn redirected(request: &HttpRequest, status: u16, location: &str) -> Option<HttpRequest> {
    let split = request.split_url();
    let url = if location.starts_with("https://") || location.starts_with("http://") {
        location.to_owned()
    } else if location.starts_with("//") {
        format!("{}:{location}", split.proto)
    } else if location.starts_with('/') {
        let default_port = matches!((split.proto, split.port), ("https", "443") | ("http", "80"));
        let authority = if default_port { split.host.to_owned() } else { format!("{}:{}", split.host, split.port) };
        format!("{}://{authority}{location}", split.proto)
    } else {
        // A path relative to the current one.
        let base = request.url.split(['?', '#']).next().unwrap_or(&request.url);
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        format!("{dir}/{location}")
    };
    if split.proto == "https" && !url.starts_with("https://") {
        return None;
    }
    let mut next = request.clone();
    next.url = url;
    let same_host = {
        let to = next.split_url();
        to.host.eq_ignore_ascii_case(split.host) && to.port == split.port
    };
    if !same_host {
        next.headers.retain(|k, _| !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie"));
    }
    use crate::types::HttpMethod;
    let to_get = (status == 303 && !matches!(request.method, HttpMethod::GET | HttpMethod::HEAD))
        || (matches!(status, 301 | 302) && matches!(request.method, HttpMethod::POST));
    if to_get {
        next.method = HttpMethod::GET;
        next.body = None;
        next.headers.retain(|k, _| !k.eq_ignore_ascii_case("content-type") && !k.eq_ignore_ascii_case("content-length"));
    }
    Some(next)
}

fn content_length_of(headers: &str) -> u64 {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    }).unwrap_or(0)
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < raw.len() {
        let line_end = find_crlf(raw, i).ok_or("invalid chunked body: missing chunk size line")?;
        let size_line = std::str::from_utf8(&raw[i..line_end])
            .map_err(|_| "invalid chunked body: chunk size line is not utf-8")?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| "invalid chunked body: bad chunk size")?;
        i = line_end + 2;

        if size == 0 {
            break;
        }
        if i + size > raw.len() {
            return Err("invalid chunked body: chunk exceeds buffer".to_string());
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size;

        if i + 2 > raw.len() || &raw[i..i + 2] != b"\r\n" {
            return Err("invalid chunked body: missing chunk terminator".to_string());
        }
        i += 2;
    }
    Ok(out)
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    data[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpMethod;

    fn req(url: &str, method: HttpMethod) -> HttpRequest {
        let mut r = HttpRequest::new(url.to_owned(), method);
        r.set_header("Authorization".into(), "Nostr x".into());
        r.set_header("User-Agent".into(), "t".into());
        r
    }

    #[test]
    fn a_blob_get_follows_to_its_storage() {
        let r = req("https://blossom.primal.net/abc.png", HttpMethod::GET);
        let next = redirected(&r, 302, "https://r2a.primal.net/uploads2/abc.png").unwrap();
        assert_eq!(next.url, "https://r2a.primal.net/uploads2/abc.png");
        assert!(matches!(next.method, HttpMethod::GET));
        // Another host: the credentials stay behind, the rest goes along.
        assert!(!next.headers.contains_key("Authorization"));
        assert!(next.headers.contains_key("User-Agent"));
    }

    #[test]
    fn relative_locations_resolve_against_the_request() {
        let r = req("https://example.com:8443/a/b?x=1", HttpMethod::GET);
        assert_eq!(redirected(&r, 301, "/c").unwrap().url, "https://example.com:8443/c");
        assert_eq!(redirected(&r, 301, "d").unwrap().url, "https://example.com:8443/a/d");
        assert_eq!(redirected(&r, 301, "//cdn.example.com/e").unwrap().url, "https://cdn.example.com/e");
        let plain = req("https://example.com/a", HttpMethod::GET);
        assert_eq!(redirected(&plain, 302, "/b").unwrap().url, "https://example.com/b");
        // Same host: the credentials go along.
        assert!(redirected(&plain, 302, "/b").unwrap().headers.contains_key("Authorization"));
    }

    #[test]
    fn never_from_https_to_http() {
        let r = req("https://example.com/a", HttpMethod::GET);
        assert!(redirected(&r, 302, "http://example.com/a").is_none());
        assert!(redirected(&req("http://example.com/a", HttpMethod::GET), 302, "https://example.com/a").is_some());
    }

    #[test]
    fn methods_change_as_the_fetch_standard_says() {
        let mut post = req("https://example.com/a", HttpMethod::POST);
        post.set_body(b"x".to_vec());
        let to_get = redirected(&post, 302, "/b").unwrap();
        assert!(matches!(to_get.method, HttpMethod::GET) && to_get.body.is_none());
        let kept = redirected(&post, 307, "/b").unwrap();
        assert!(matches!(kept.method, HttpMethod::POST) && kept.body.is_some());
        // A Blossom upload (PUT) stays a PUT on a 302; a 303 makes it a GET.
        let put = req("https://example.com/upload", HttpMethod::PUT);
        assert!(matches!(redirected(&put, 302, "/up2").unwrap().method, HttpMethod::PUT));
        assert!(matches!(redirected(&put, 303, "/done").unwrap().method, HttpMethod::GET));
    }

    #[test]
    fn location_is_read_from_the_headers() {
        let h = "Content-Type: image/png\nLocation: https://x.example/a\n";
        assert_eq!(header_of(h, "location"), Some("https://x.example/a"));
        assert_eq!(header_of(h, "etag"), None);
    }
}
