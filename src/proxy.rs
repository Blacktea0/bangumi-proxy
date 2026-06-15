use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use crate::backend::open_backend;
use crate::ca::MitmCa;
use crate::ech::EchCache;
use crate::targets::is_target;

pub fn handle_client(mut client: TcpStream, cache: Arc<EchCache>, ca: Arc<MitmCa>) {
    let peer = client
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() || req_line.is_empty() {
        return;
    }

    let req_line = req_line.trim_end().to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        headers.push(line.trim_end().to_string());
    }

    let method = req_line.split_whitespace().next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_request(&mut client, &req_line, &cache, &peer, &ca);
    } else {
        handle_http_request(client, reader, req_line, headers, &cache, &peer);
    }
}

fn handle_connect_request(
    client: &mut TcpStream,
    req_line: &str,
    cache: &EchCache,
    peer: &str,
    ca: &MitmCa,
) {
    let target = req_line.split_whitespace().nth(1).unwrap_or("");
    let (host, _) = target
        .rsplit_once(':')
        .map(|(host, port)| (host, port.parse().unwrap_or(443)))
        .unwrap_or((target, 443));
    println!("[{peer}] CONNECT {target}");
    handle_connect(client, host, cache, peer, ca);
}

fn handle_connect(client: &mut TcpStream, host: &str, cache: &EchCache, peer: &str, ca: &MitmCa) {
    if is_target(host) {
        handle_mitm(client, host, cache, peer, ca);
    } else {
        handle_tunnel(client, host, cache, peer);
    }
}

/// Raw TCP tunnel - relay bytes between browser and remote server without decryption.
fn handle_tunnel(client: &mut TcpStream, host: &str, cache: &EchCache, peer: &str) {
    let connect_addr = cache
        .hosts
        .get(host)
        .map(|ip| format!("{ip}:443"))
        .unwrap_or_else(|| format!("{host}:443"));
    let mut remote = match TcpStream::connect(&connect_addr) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("[{peer}] tunnel {host}: {err}");
            return;
        }
    };
    remote
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    remote
        .set_write_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let _ = client.flush();
    println!("[{peer}] TUNNEL {host} -> {connect_addr}");

    client.set_nonblocking(true).ok();
    remote.set_nonblocking(true).ok();
    relay_plain(client, &mut remote);
    client.set_nonblocking(false).ok();
}

fn handle_mitm(client: &mut TcpStream, host: &str, cache: &EchCache, peer: &str, ca: &MitmCa) {
    let mut backend = match open_backend(host, cache) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("[{peer}] backend: {err}");
            return;
        }
    };

    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let _ = client.flush();

    let config = Arc::new(ca.server_config(host));
    let mut acceptor = rustls::server::Acceptor::default();
    let mut tcp = client.try_clone().unwrap();
    let accepted = loop {
        match acceptor.accept() {
            Ok(Some(accepted)) => break accepted,
            Ok(None) => {
                let mut buf = [0u8; 4096];
                match tcp.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if acceptor.read_tls(&mut &buf[..n]).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
            Err((_, _)) => return,
        }
    };

    let sni = {
        let client_hello = accepted.client_hello();
        client_hello.server_name().unwrap_or("(none)").to_string()
    };
    println!("[{peer}] MITM TLS: SNI={sni}");
    let mut browser_tls = match accepted.into_connection(config) {
        Ok(conn) => conn,
        Err((_, _)) => return,
    };
    println!("[{peer}] MITM OK for {host}");

    client.set_nonblocking(true).ok();
    backend.get_ref().set_nonblocking(true).ok();
    {
        let mut browser_stream = rustls::Stream::new(&mut browser_tls, &mut *client);
        relay_tls(&mut browser_stream, &mut backend);
    }
    client.set_nonblocking(false).ok();
}

fn handle_http_request(
    mut client: TcpStream,
    mut reader: BufReader<TcpStream>,
    req_line: String,
    headers: Vec<String>,
    cache: &EchCache,
    peer: &str,
) {
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let (method, uri) = (parts[0], parts[1]);
    let host = request_host(uri, &headers);
    let path = request_path(uri);
    println!("[{peer}] {method} {path} (host={host})");
    if !is_target(host) {
        println!("[{peer}] {host} (direct)");
    }

    let content_len = headers
        .iter()
        .find(|header| header.to_lowercase().starts_with("content-length:"))
        .and_then(|header| header.split(':').nth(1))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        let _ = reader.read_exact(&mut body);
    }

    let mut backend = match open_backend(host, cache) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("[err] {err}");
            return;
        }
    };

    let _ = backend.write_all(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for header in &headers {
        let lower = header.to_lowercase();
        if lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authenticate:") {
            continue;
        }
        let _ = backend.write_all(format!("{header}\r\n").as_bytes());
    }
    let _ = backend.write_all(b"\r\n");
    if !body.is_empty() {
        let _ = backend.write_all(&body);
    }
    let _ = backend.flush();

    client.set_nonblocking(true).ok();
    backend.get_ref().set_nonblocking(true).ok();
    relay_tls(&mut client, &mut backend);
    client.set_nonblocking(false).ok();
}

fn request_host<'a>(uri: &'a str, headers: &'a [String]) -> &'a str {
    if let Some(rest) = uri.strip_prefix("http://") {
        return rest
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
    }

    headers
        .iter()
        .find(|header| header.to_lowercase().starts_with("host:"))
        .and_then(|header| header.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("")
}

fn request_path(uri: &str) -> &str {
    if let Some(rest) = uri.strip_prefix("http://") {
        match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        }
    } else {
        uri
    }
}

fn relay_plain(client: &mut TcpStream, remote: &mut TcpStream) {
    loop {
        let mut buf = [0u8; 8192];
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = remote.write_all(&buf[..n]);
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        match remote.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = client.write_all(&buf[..n]);
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn relay_tls<C, B>(client: &mut C, backend: &mut B)
where
    C: Read + Write,
    B: Read + Write,
{
    loop {
        let mut buf = [0u8; 8192];
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = backend.write_all(&buf[..n]);
                let _ = backend.flush();
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(ref err) if err.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
        match backend.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = client.write_all(&buf[..n]);
                let _ = client.flush();
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(ref err) if err.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
        thread::sleep(std::time::Duration::from_millis(1));
    }
}
