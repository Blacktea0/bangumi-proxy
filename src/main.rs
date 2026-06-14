use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use foreign_types_shared::ForeignType;
use foreign_types_shared::ForeignTypeRef;
use parking_lot::Mutex;

unsafe extern "C" {
    fn ech_get_retry_config(
        host: *const std::os::raw::c_char, port: std::os::raw::c_int,
        outer_sni: *const std::os::raw::c_char, out_cfg: *mut *mut u8, out_len: *mut usize,
    ) -> std::os::raw::c_int;
    fn ech_free(p: *mut std::os::raw::c_void);
}

mod ffi {
    use std::os::raw::{c_char, c_int};
    unsafe extern "C" {
        pub fn SSL_set1_ech_config_list(s: *mut openssl_sys::SSL, ecl: *const u8, len: usize) -> c_int;
        pub fn SSL_ech_set1_server_names(s: *mut openssl_sys::SSL, inner: *const c_char, outer: *const c_char, no_outer: c_int) -> c_int;
        pub fn SSL_ech_get1_status(s: *mut openssl_sys::SSL, inner: *mut *mut c_char, outer: *mut *mut c_char) -> c_int;
    }
}

const OUTER_SNI: &str = "cloudflare-ech.com";
const PROXY_ADDR: &str = "127.0.0.1:8080";
const TARGETS: &[&str] = &["chii.in", "lain.bgm.tv", "bgm.tv"];
// bgm.tv 不在 Cloudflare 上，但保留在列表中以便未来切换 CDN 后自动生效

fn is_target(host: &str) -> bool {
    TARGETS.iter().any(|&t| host == t || host.ends_with(&format!(".{t}")))
}
struct EchCache {
    config: Mutex<Option<Vec<u8>>>,
    ips: Mutex<HashMap<String, std::net::Ipv4Addr>>,
}

use std::collections::HashMap;

impl EchCache {
    fn new() -> Self {
        Self {
            config: Mutex::new(None),
            ips: Mutex::new(HashMap::new()),
        }
    }

    fn get_ech(&self, host: &str) -> io::Result<Vec<u8>> {
        if let Some(cfg) = &*self.config.lock() { return Ok(cfg.clone()); }
        // Use this host's Cloudflare IP for GREASE
        let ip = self.get_ip(host)?;
        println!("[ECH] GREASE → {ip}…");
        let cfg = grease_ech(ip)?;
        println!("[ECH] {} byte retry-config", cfg.len());
        *self.config.lock() = Some(cfg.clone());
        Ok(cfg)
    }

    fn get_ip(&self, host: &str) -> io::Result<std::net::Ipv4Addr> {
        if let Some(ip) = self.ips.lock().get(host) { return Ok(*ip); }
        println!("[DNS] Resolving {host}…");
        let ip = resolve_cf_ip(host)?;
        println!("[DNS] {host} → {ip}");
        self.ips.lock().insert(host.to_string(), ip);
        Ok(ip)
    }

    fn invalidate(&self) { self.config.lock().take(); }
}
// ============================= DNS ==========================================

fn tls_skip() -> openssl::ssl::SslConnector {
    let mut b = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
    b.set_verify(openssl::ssl::SslVerifyMode::NONE);
    b.build()
}

fn doh_json(host: &str, path: &str) -> io::Result<String> {
    let tcp = TcpStream::connect(format!("{host}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut s = tls_skip()
        .connect(host, tcp)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    s.flush()?;
    let mut buf = vec![];
    s.read_to_end(&mut buf)?;
    let h = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
    String::from_utf8(buf[h + 4..].to_vec()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))
}

fn resolve_cf_ip(host: &str) -> io::Result<std::net::Ipv4Addr> {
    let j = doh_json("doh.pub", &format!("/dns-query?name={host}&type=A"))?;
    let ans_start = j
        .find("\"Answer\"")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Answer"))?;
    let ans = &j[ans_start..];
    let data_pos = ans
        .find("\"data\":\"")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no data"))?;
    let after = &ans[data_pos + 8..];
    let end = after
        .find('"')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quote"))?;
    after[..end]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("bad IP: {}", &after[..end])))
}
fn grease_ech(ip: std::net::Ipv4Addr) -> io::Result<Vec<u8>> {
    let host = std::ffi::CString::new(ip.to_string()).unwrap();
    let sni = std::ffi::CString::new(OUTER_SNI).unwrap();
    let (mut cfg, mut len): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    let r = unsafe { ech_get_retry_config(host.as_ptr(), 443, sni.as_ptr(), &mut cfg, &mut len) };
    if r == 1 && !cfg.is_null() && len > 0 {
        let data = unsafe { std::slice::from_raw_parts(cfg, len).to_vec() };
        unsafe { ech_free(cfg as *mut _) };
        Ok(data)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "GREASE ECH failed"))
    }
}
static INIT: std::sync::Once = std::sync::Once::new();

fn connect_backend(host: &str, ip: std::net::Ipv4Addr, ecl: &[u8]) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    INIT.call_once(|| openssl::init());
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build();
    let ssl = openssl::ssl::Ssl::new(&ctx)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let r = unsafe { ffi::SSL_set1_ech_config_list(ssl.as_ptr(), ecl.as_ptr(), ecl.len()) };
    if r != 1 { return Err(io::Error::new(io::ErrorKind::Other, format!("ech_config failed ({r})"))); }
    let ci = std::ffi::CString::new(host).unwrap();
    let co = std::ffi::CString::new(OUTER_SNI).unwrap();
    unsafe { ffi::SSL_ech_set1_server_names(ssl.as_ptr(), ci.as_ptr(), co.as_ptr(), 0) };
    let tcp = TcpStream::connect(format!("{ip}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let stream = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let st = unsafe { ffi::SSL_ech_get1_status(stream.ssl().as_ptr(), std::ptr::null_mut(), std::ptr::null_mut()) };
    println!("[ECH] {host} → {ip} status={st}");
    Ok(stream)
}

// ============================= Proxy handler ================================

/// Helper: resolve ECH config + IP, then connect to backend.
fn open_backend(host: &str, cache: &EchCache) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    let ecl = cache.get_ech(host)?;
    let ip = cache.get_ip(host)?;
    match connect_backend(host, ip, &ecl) {
        Ok(s) => Ok(s),
        Err(e) => { cache.invalidate(); Err(e) }
    }
}

fn handle_client(mut client: TcpStream, cache: Arc<EchCache>) {
    let peer = client.peer_addr().ok();
    let ps = peer.map(|p| p.to_string()).unwrap_or_default();
    let mut reader = BufReader::new(client.try_clone().unwrap());

    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() || req_line.is_empty() { return; }
    let req_line = req_line.trim_end().to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() { break; }
        headers.push(line.trim_end().to_string());
    }

    let method = req_line.split_whitespace().next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = req_line.split_whitespace().nth(1).unwrap_or("");
        let (host, _) = match target.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(443)),
            None => (target, 443),
        };
        println!("[{ps}] CONNECT {target}");
        if !is_target(host) {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked: only bgm.tv domains are proxied\r\n");
            return;
        }
        let mut backend = match open_backend(host, &cache) {
            Ok(s) => s,
            Err(e) => { eprintln!("[err] {e}"); return; }
        };
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = client.flush();
        relay(&mut client, &mut backend);
    } else {
        let parts: Vec<&str> = req_line.split_whitespace().collect();
        if parts.len() < 3 { return; }
        let (method, uri) = (parts[0], parts[1]);
        let host = if uri.starts_with("http://") {
            uri[7..].split('/').next().unwrap_or("").split(':').next().unwrap_or("")
        } else {
            headers.iter().find(|h| h.to_lowercase().starts_with("host:"))
                .and_then(|h| h.split(':').nth(1)).map(str::trim).unwrap_or("")
        };
        let path = if uri.starts_with("http://") {
            match &uri[7..].find('/') { Some(i) => &uri[7+i..], None => "/" }
        } else { uri };
        println!("[{ps}] {method} {path} (host={host})");
        if !is_target(host) {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked: only bgm.tv domains are proxied\r\n");
            return;
        }
        let cl: usize = headers.iter().find(|h| h.to_lowercase().starts_with("content-length:"))
            .and_then(|h| h.split(':').nth(1)).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let mut body = vec![0u8; cl];
        if cl > 0 { let _ = reader.read_exact(&mut body); }

        let mut backend = match open_backend(host, &cache) {
            Ok(s) => s,
            Err(e) => { eprintln!("[err] {e}"); return; }
        };
        let _ = backend.write_all(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
        for h in &headers {
            let l = h.to_lowercase();
            if l.starts_with("proxy-connection:") || l.starts_with("proxy-authenticate:") { continue; }
            let _ = backend.write_all(format!("{h}\r\n").as_bytes());
        }
        let _ = backend.write_all(b"\r\n");
        if !body.is_empty() { let _ = backend.write_all(&body); }
        let _ = backend.flush();
        relay(&mut client, &mut backend);
    }
}
/// Bidirectional relay: client ↔ backend.
fn relay(client: &mut TcpStream, backend: &mut openssl::ssl::SslStream<TcpStream>) {
    client.set_nonblocking(true).ok();
    backend.get_ref().set_nonblocking(true).ok();

    let mut done = false;
    while !done {
        let mut buf = [0u8; 8192];
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { let _ = backend.write_all(&buf[..n]); let _ = backend.flush(); }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        match backend.read(&mut buf) {
            Ok(0) => done = true,
            Ok(n) => { let _ = client.write_all(&buf[..n]); let _ = client.flush(); }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        thread::sleep(std::time::Duration::from_millis(1));
    }
    client.set_nonblocking(false).ok();
}

fn main() -> io::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  bangumi-proxy — HTTP 代理 + ECH 绕过 GFW                    ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  代理:  http://{PROXY_ADDR:<42} ║");
    println!("║  站点:  chii.in / lain.bgm.tv / bgm.tv                    ║");
    println!("║  SNI:   {OUTER_SNI} (外层, 绕过 GFW)                   ║");
    println!("║  用法:  浏览器 HTTP 代理 → 127.0.0.1:8080                  ║");
    println!("║         访问 http://chii.in / http://bgm.tv 等             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let cache = Arc::new(EchCache::new());
    let listener = TcpListener::bind(PROXY_ADDR)?;
    println!("[proxy] Listening on {PROXY_ADDR}\n");

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let cache = Arc::clone(&cache);
            thread::spawn(move || handle_client(client, cache));
        }
    }
    Ok(())
}
