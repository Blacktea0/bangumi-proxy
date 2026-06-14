use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread;

use clap::Parser;
use foreign_types_shared::ForeignType;
use foreign_types_shared::ForeignTypeRef;
use parking_lot::Mutex;

unsafe extern "C" {
    fn ech_get_retry_config(host: *const std::os::raw::c_char, port: std::os::raw::c_int, outer_sni: *const std::os::raw::c_char, out_cfg: *mut *mut u8, out_len: *mut usize) -> std::os::raw::c_int;
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
const TARGETS: &[&str] = &["chii.in", "lain.bgm.tv", "bgm.tv"];
const CF_DOH_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(1, 1, 1, 1);
const CF_DOH_HOST: &str = "cloudflare-dns.com";

#[derive(Parser, Debug)]
#[command(name = "bangumi-proxy", version, about = "HTTP/HTTPS proxy + ECH")]
struct Args {
    #[arg(short, long, default_value_t = 8080)] port: u16,
    #[arg(short, long)] browser: bool,
    #[arg(short, long, default_value = "http://chii.in")] url: String,
    #[arg(long)] chrome: Option<String>,
    /// DoH URL or plain DNS IP
    #[arg(long, default_value = "https://doh.pub/dns-query")] dns: String,
    /// 直接指定目标 Cloudflare IP，跳过 DNS
    #[arg(long)] ip: Option<String>,
}

fn is_target(host: &str) -> bool { TARGETS.iter().any(|&t| host == t || host.ends_with(&format!(".{t}"))) }

// ============================= CA ===========================================

struct MitmCa { ca_key: rcgen::KeyPair, ca_cert: rcgen::Certificate }
impl MitmCa {
    fn load_or_generate() -> Self {
        let cp = std::env::current_dir().unwrap_or_default().join("ca.pem");
        let kp = std::env::current_dir().unwrap_or_default().join("ca-key.pem");
        if cp.exists() && kp.exists() {
            println!("[CA] Loaded from {}", cp.display());
            let key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&kp).unwrap()).unwrap();
            let mut p = rcgen::CertificateParams::new(vec!["bangumi-proxy CA".into()]).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            return Self { ca_cert: p.self_signed(&key).unwrap(), ca_key: key };
        }
        println!("[CA] Generating…");
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["bangumi-proxy CA".into()]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = p.self_signed(&key).unwrap();
        std::fs::write(&cp, cert.pem()).unwrap();
        std::fs::write(&kp, key.serialize_pem()).unwrap();
        println!("[CA] Saved to {}", cp.display());
        Self { ca_cert: cert, ca_key: key }
    }
    fn server_config(&self, host: &str) -> rustls::ServerConfig {
        let hk = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        let hc = p.signed_by(&hk, &self.ca_cert, &self.ca_key).unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(hc.der().to_vec())];
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(hk.serialize_der());
        rustls::ServerConfig::builder().with_no_client_auth()
            .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::from(key)).unwrap()
    }
}

// ============================= ECH cache ====================================

struct EchCache {
    config: Mutex<Option<Vec<u8>>>,
    ips: Mutex<std::collections::HashMap<String, std::net::Ipv4Addr>>,
    dns: String,
    fixed_ip: Option<std::net::Ipv4Addr>,
}
impl EchCache {
    fn new(dns: String, fixed_ip: Option<std::net::Ipv4Addr>) -> Self {
        Self { config: Mutex::new(None), ips: Mutex::new(std::collections::HashMap::new()), dns, fixed_ip }
    }
    fn get_ech(&self) -> io::Result<Vec<u8>> {
        if let Some(c) = &*self.config.lock() { return Ok(c.clone()); }
        let ip = self.resolve_host(CF_DOH_HOST)?;
        println!("[ECH] {CF_DOH_HOST} → {ip}, GREASE…");
        let c = grease_ech(ip)?;
        println!("[ECH] {} bytes", c.len());
        *self.config.lock() = Some(c.clone());
        Ok(c)
    }
    fn get_ip(&self, host: &str) -> io::Result<std::net::Ipv4Addr> {
        // --ip: skip DNS entirely
        if let Some(ip) = self.fixed_ip { return Ok(ip); }
        if let Some(ip) = self.ips.lock().get(host) { return Ok(*ip); }
        let ip = match self.resolve_via_ech(host) {
            Ok(ip) => { println!("[DNS] {host} → {ip} (ECH)"); ip }
            Err(e) => { eprintln!("[DNS] ECH: {e}"); let ip = self.resolve_host(host)?; println!("[DNS] {host} → {ip} ({})", self.dns); ip }
        };
        self.ips.lock().insert(host.to_string(), ip);
        Ok(ip)
    }
    fn resolve_host(&self, host: &str) -> io::Result<std::net::Ipv4Addr> {
        if self.dns.starts_with("http") {
            let base = self.dns.trim_start_matches("https://").trim_start_matches("http://");
            let (doh_host, path) = base.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((base, "/dns-query".into()));
            let j = doh_json(doh_host, &format!("{path}?name={host}&type=A"))?;
            parse_a(&j).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
        } else {
            let server = if self.dns.parse::<std::net::Ipv4Addr>().is_ok() {
                self.dns.clone()
            } else {
                format!("{}:53", self.dns).to_socket_addrs()?
                    .find(|a| a.is_ipv4()).map(|a| a.ip().to_string())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "can't resolve DNS server"))?
            };
            resolve_plain_dns(&server, host)
        }
    }
    fn resolve_via_ech(&self, host: &str) -> io::Result<std::net::Ipv4Addr> {
        let ecl = self.get_ech()?;
        let mut b = connect_ech(CF_DOH_HOST, CF_DOH_IP, &ecl)?;
        b.write_all(format!("GET /dns-query?name={host}&type=A HTTP/1.1\r\nHost: {CF_DOH_HOST}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n").as_bytes())?;
        b.flush()?;
        let mut buf = vec![]; b.read_to_end(&mut buf)?;
        let h = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
        parse_a(&String::from_utf8_lossy(&buf[h+4..])).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
    }
    fn invalidate(&self) { self.config.lock().take(); }
}

// ============================= DNS =========================================

fn tls_skip() -> openssl::ssl::SslConnector {
    let mut b = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
    b.set_verify(openssl::ssl::SslVerifyMode::NONE); b.build()
}
fn doh_json(host: &str, path: &str) -> io::Result<String> {
    let tcp = TcpStream::connect(format!("{host}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut s = tls_skip().connect(host, tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n").as_bytes())?;
    s.flush()?;
    let mut buf = vec![]; s.read_to_end(&mut buf)?;
    let h = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
    String::from_utf8(buf[h+4..].to_vec()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))
}
fn parse_a(j: &str) -> Option<std::net::Ipv4Addr> {
    let i = j.find("\"Answer\"")?; let d = j[i..].find("\"data\":\"")?; let a = &j[i+d+8..]; let e = a.find('"')?; a[..e].parse().ok()
}
fn skip_name(data: &[u8], mut p: usize) -> io::Result<usize> {
    loop { if p >= data.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "overflow")); } let b = data[p]; if b == 0 { return Ok(p+1); } if b & 0xC0 == 0xC0 { return Ok(p+2); } p += 1 + b as usize; }
}
fn resolve_plain_dns(server: &str, host: &str) -> io::Result<std::net::Ipv4Addr> {
    let txid: u16 = 0x1234;
    let mut pkt = Vec::with_capacity(512);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[1,0, 0,1, 0,0, 0,0, 0,0]);
    for l in host.split('.') { pkt.push(l.len() as u8); pkt.extend_from_slice(l.as_bytes()); }
    pkt.push(0); pkt.extend_from_slice(&[0,1, 0,1]);
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, format!("{server}:53"))?;
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf)?;
    let r = &buf[..n];
    if r.len() < 12 || u16::from_be_bytes([r[0],r[1]]) != txid { return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS")); }
    let an = u16::from_be_bytes([r[6],r[7]]) as usize;
    let mut p = skip_name(r, 12)? + 4;
    for _ in 0..an { p = skip_name(r, p)?; if p+10 > r.len() { break; } let t = u16::from_be_bytes([r[p],r[p+1]]); let rl = u16::from_be_bytes([r[p+8],r[p+9]]) as usize; p += 10; if t == 1 && rl == 4 && p+4 <= r.len() { return Ok(std::net::Ipv4Addr::new(r[p],r[p+1],r[p+2],r[p+3])); } p += rl; }
    Err(io::Error::new(io::ErrorKind::NotFound, "no A"))
}
fn grease_ech(ip: std::net::Ipv4Addr) -> io::Result<Vec<u8>> {
    let h = std::ffi::CString::new(ip.to_string()).unwrap(); let s = std::ffi::CString::new(OUTER_SNI).unwrap();
    let (mut c, mut l): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    let r = unsafe { ech_get_retry_config(h.as_ptr(), 443, s.as_ptr(), &mut c, &mut l) };
    if r == 1 && !c.is_null() && l > 0 { let d = unsafe { std::slice::from_raw_parts(c, l).to_vec() }; unsafe { ech_free(c as *mut _) }; Ok(d) }
    else { Err(io::Error::new(io::ErrorKind::Other, "GREASE failed")) }
}

// ============================= ECH backend ==================================

static INIT: std::sync::Once = std::sync::Once::new();
fn connect_ech(host: &str, ip: std::net::Ipv4Addr, ecl: &[u8]) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    INIT.call_once(|| openssl::init());
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build(); let ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    if unsafe { ffi::SSL_set1_ech_config_list(ssl.as_ptr(), ecl.as_ptr(), ecl.len()) } != 1 { return Err(io::Error::new(io::ErrorKind::Other, "ech_config")); }
    let ci = std::ffi::CString::new(host).unwrap(); let co = std::ffi::CString::new(OUTER_SNI).unwrap();
    unsafe { ffi::SSL_ech_set1_server_names(ssl.as_ptr(), ci.as_ptr(), co.as_ptr(), 0) };
    let tcp = TcpStream::connect(format!("{ip}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?; tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let st = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let s = unsafe { ffi::SSL_ech_get1_status(st.ssl().as_ptr(), std::ptr::null_mut(), std::ptr::null_mut()) };
    println!("[ECH] {host} → {ip} status={s}");
    Ok(st)
}
/// Direct TLS connection (no ECH) for non-Cloudflare domains.
fn connect_direct(host: &str) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    INIT.call_once(|| openssl::init());
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build();
    let ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let host_c = std::ffi::CString::new(host).unwrap();
    unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), host_c.as_ptr() as *mut _) };
    let tcp = TcpStream::connect(format!("{host}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    let st = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    println!("[TLS] {host} (direct)");
    Ok(st)
}

fn open_backend(host: &str, cache: &EchCache) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    // Target domains: use ECH. Others: try ECH first, fall back to direct.
    if is_target(host) {
        let ecl = cache.get_ech()?; let ip = cache.get_ip(host)?;
        return match connect_ech(host, ip, &ecl) { Ok(s) => Ok(s), Err(e) => { cache.invalidate(); Err(e) } };
    }
    // Non-target: try ECH (if DNS gives us a Cloudflare IP), then direct
    match cache.get_ip(host) {
        Ok(ip) if is_cloudflare_ip(ip) => {
            if let Ok(ecl) = cache.get_ech() {
                if let Ok(s) = connect_ech(host, ip, &ecl) { return Ok(s); }
            }
        }
        _ => {}
    }
    connect_direct(host)
}

fn is_cloudflare_ip(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 104 || o[0] == 172 && o[1] >= 64 && o[1] <= 95 || o[0] == 162 && o[1] == 159 || o[0] == 188 && o[1] == 114
}

fn handle_connect(client: &mut TcpStream, host: &str, cache: &EchCache, ps: &str, ca: &MitmCa) {
    if is_target(host) {
        // Target domain: MITM TLS + ECH
        handle_mitm(client, host, cache, ps, ca);
    } else {
        // Other domain: raw tunnel (no MITM, no ECH)
        handle_tunnel(client, host, ps);
    }
}

/// Raw TCP tunnel — relay bytes between browser and remote server without decryption.
fn handle_tunnel(client: &mut TcpStream, host: &str, ps: &str) {
    let mut remote = match TcpStream::connect(format!("{host}:443")) {
        Ok(s) => s,
        Err(e) => { eprintln!("[{ps}] tunnel {host}: {e}"); return; }
    };
    remote.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();
    remote.set_write_timeout(Some(std::time::Duration::from_secs(60))).ok();
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let _ = client.flush();
    println!("[{ps}] TUNNEL {host}:443");

    client.set_nonblocking(true).ok();
    remote.set_nonblocking(true).ok();
    loop {
        let mut buf = [0u8; 8192];
        match client.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = remote.write_all(&buf[..n]); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(_) => break }
        match remote.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = client.write_all(&buf[..n]); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(_) => break }
        thread::sleep(std::time::Duration::from_millis(1));
    }
    client.set_nonblocking(false).ok();
}

/// MITM TLS — decrypt browser TLS, forward via ECH to Cloudflare backend.
fn handle_mitm(client: &mut TcpStream, host: &str, cache: &EchCache, ps: &str, ca: &MitmCa) {
    let mut backend = match open_backend(host, cache) { Ok(s) => s, Err(e) => { eprintln!("[{ps}] backend: {e}"); return; } };
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"); let _ = client.flush();
    let config = Arc::new(ca.server_config(host));
    let mut acceptor = rustls::server::Acceptor::default();
    let mut tcp = client.try_clone().unwrap();
    let accepted = loop {
        match acceptor.accept() {
            Ok(Some(a)) => break a,
            Ok(None) => { let mut buf = [0u8; 4096]; match tcp.read(&mut buf) { Ok(0) => return, Ok(n) => { if acceptor.read_tls(&mut &buf[..n]).is_err() { return; } } Err(_) => return, } }
            Err((_, _)) => return,
        }
    };
    let sni = { let ch = accepted.client_hello(); ch.server_name().unwrap_or("(none)").to_string() };
    println!("[{ps}] MITM TLS: SNI={sni}");
    let mut browser_tls = match accepted.into_connection(config) { Ok(c) => c, Err((_, _)) => return };
    println!("[{ps}] MITM OK for {host}");
    client.set_nonblocking(true).ok(); backend.get_ref().set_nonblocking(true).ok();
    {
        let mut bs = rustls::Stream::new(&mut browser_tls, &mut *client);
        loop {
            let mut buf = [0u8; 8192];
            match bs.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = backend.write_all(&buf[..n]); let _ = backend.flush(); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break, Err(_) => break }
            match backend.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = bs.write_all(&buf[..n]); let _ = bs.flush(); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break, Err(_) => break }
            thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    client.set_nonblocking(false).ok();
}

// ============================= Proxy ========================================

fn handle_client(mut client: TcpStream, cache: Arc<EchCache>, ca: Arc<MitmCa>) {
    let ps = client.peer_addr().map(|p| p.to_string()).unwrap_or_default();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() || req_line.is_empty() { return; }
    let req_line = req_line.trim_end().to_string();
    let mut headers = Vec::new();
    loop { let mut l = String::new(); if reader.read_line(&mut l).is_err() || l == "\r\n" || l.is_empty() { break; } headers.push(l.trim_end().to_string()); }
    let method = req_line.split_whitespace().next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        let target = req_line.split_whitespace().nth(1).unwrap_or("");
        let (host, _) = target.rsplit_once(':').map(|(h, p)| (h, p.parse().unwrap_or(443))).unwrap_or((target, 443));
        println!("[{ps}] CONNECT {target}");
        handle_connect(&mut client, host, &cache, &ps, &ca);
    } else {
        let parts: Vec<&str> = req_line.split_whitespace().collect();
        let (method, uri) = (parts[0], parts[1]);
        let host = if uri.starts_with("http://") { uri[7..].split('/').next().unwrap_or("").split(':').next().unwrap_or("") } else { headers.iter().find(|h| h.to_lowercase().starts_with("host:")).and_then(|h| h.split(':').nth(1)).map(str::trim).unwrap_or("") };
        let path = if uri.starts_with("http://") { match &uri[7..].find('/') { Some(i) => &uri[7+i..], None => "/" } } else { uri };
        println!("[{ps}] {method} {path} (host={host})");
        if !is_target(host) { println!("[{ps}] {host} (direct)"); }
        let cl: usize = headers.iter().find(|h| h.to_lowercase().starts_with("content-length:")).and_then(|h| h.split(':').nth(1)).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let mut body = vec![0u8; cl]; if cl > 0 { let _ = reader.read_exact(&mut body); }
        let mut backend = match open_backend(host, &cache) { Ok(s) => s, Err(e) => { eprintln!("[err] {e}"); return; } };
        let _ = backend.write_all(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
        for h in &headers { let l = h.to_lowercase(); if l.starts_with("proxy-connection:") || l.starts_with("proxy-authenticate:") { continue; } let _ = backend.write_all(format!("{h}\r\n").as_bytes()); }
        let _ = backend.write_all(b"\r\n"); if !body.is_empty() { let _ = backend.write_all(&body); } let _ = backend.flush();
        client.set_nonblocking(true).ok(); backend.get_ref().set_nonblocking(true).ok();
        loop {
            let mut buf = [0u8; 8192];
            match client.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = backend.write_all(&buf[..n]); let _ = backend.flush(); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(_) => break }
            match backend.read(&mut buf) { Ok(0) => break, Ok(n) => { let _ = client.write_all(&buf[..n]); let _ = client.flush(); } Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {} Err(_) => break }
            thread::sleep(std::time::Duration::from_millis(1));
        }
        client.set_nonblocking(false).ok();
    }
}

// ============================= Browser ======================================

fn find_chrome() -> Option<String> {
    for c in &["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe", "C:/Program Files/Microsoft/Edge/Application/msedge.exe"] {
        if std::path::Path::new(c).exists() { return Some(c.to_string()); }
    }
    which::which("chrome").ok().or_else(|| which::which("msedge").ok()).map(|p| p.display().to_string())
}
fn launch_browser(chrome: &str, proxy: &str, url: &str) {
    let p = format!("{}/bangumi-proxy-chrome", std::env::temp_dir().display());
    println!("[browser] {chrome} proxy=http://{proxy} url={url}\n");
    let _ = std::process::Command::new(chrome).args([format!("--proxy-server=http://{proxy}"), "--remote-debugging-port=9222".into(), "--no-first-run".into(), "--no-default-browser-check".into(), format!("--user-data-dir={p}"), "--ignore-certificate-errors".into(), url.into()]).spawn();
}

// ============================= main =========================================

fn main() -> io::Result<()> {
    let args = Args::parse();
    let addr = format!("127.0.0.1:{}", args.port);
    let ca = Arc::new(MitmCa::load_or_generate());
    let fixed_ip = args.ip.as_ref().and_then(|s| s.parse().ok());

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  bangumi-proxy — HTTP/HTTPS + ECH 绕过 GFW                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  代理: http://{addr:<44}║");
    println!("║  站点: chii.in / lain.bgm.tv / bgm.tv                     ║");
    println!("║  DNS:  {:<52} ║", if fixed_ip.is_some() { format!("fixed → {}", args.ip.as_deref().unwrap()) } else { args.dns.clone() });
    println!("║  MITM: 自签 CA，支持 HTTPS                                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let cache = Arc::new(EchCache::new(args.dns.clone(), fixed_ip));
    let listener = TcpListener::bind(&addr)?;
    println!("[proxy] Listening on {addr}\n");

    if args.browser {
        let chrome = args.chrome.clone().or_else(find_chrome).unwrap_or_else(|| { eprintln!("[browser] Chrome not found"); std::process::exit(1); });
        launch_browser(&chrome, &addr, &args.url);
    } else { println!("Tip: use -b to auto-launch Chrome\n"); }

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let (cache, ca) = (Arc::clone(&cache), Arc::clone(&ca));
            thread::spawn(move || handle_client(client, cache, ca));
        }
    }
    Ok(())
}
