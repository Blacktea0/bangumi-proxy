use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread;

use clap::Parser;
use foreign_types_shared::ForeignType;
#[cfg(has_ech)]
use foreign_types_shared::ForeignTypeRef;
use parking_lot::Mutex;

#[cfg(has_ech)]
unsafe extern "C" {
    fn ech_get_retry_config(host: *const std::os::raw::c_char, port: std::os::raw::c_int, outer_sni: *const std::os::raw::c_char, out_cfg: *mut *mut u8, out_len: *mut usize) -> std::os::raw::c_int;
    fn ech_free(p: *mut std::os::raw::c_void);
}
#[cfg(has_ech)]
mod ffi {
    use std::os::raw::{c_char, c_int};
    unsafe extern "C" {
        pub fn SSL_set1_ech_config_list(s: *mut openssl_sys::SSL, ecl: *const u8, len: usize) -> c_int;
        pub fn SSL_ech_set1_server_names(s: *mut openssl_sys::SSL, inner: *const c_char, outer: *const c_char, no_outer: c_int) -> c_int;
        pub fn SSL_ech_get1_status(s: *mut openssl_sys::SSL, inner: *mut *mut c_char, outer: *mut *mut c_char) -> c_int;
    }
}

#[cfg(has_ech)]
const OUTER_SNI: &str = "cloudflare-ech.com";
const TARGETS: &[&str] = &["chii.in", "lain.bgm.tv", "bgm.tv", "next.bgm.tv"];
const CF_DOH_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(104, 16, 248, 249);
const CF_DOH_HOST: &str = "cloudflare-dns.com";

/// Parse a standard hosts file (IP domain1 [domain2 ...]).
fn parse_hosts(path: &str) -> std::collections::HashMap<String, std::net::Ipv4Addr> {
    let mut map = std::collections::HashMap::new();
    let data = match std::fs::read_to_string(path) { Ok(d) => d, Err(e) => { eprintln!("[hosts] {path}: {e}"); return map; } };
    for line in data.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let mut parts = line.split_whitespace();
        let ip: std::net::Ipv4Addr = match parts.next().and_then(|s| s.parse().ok()) { Some(ip) => ip, None => continue };
        for domain in parts { map.insert(domain.to_lowercase(), ip); }
    }
    map
}

#[derive(Parser, Debug)]
#[command(name = "bangumi-proxy", version, about = "HTTP/HTTPS proxy + ECH")]
struct Args {
    #[arg(short, long, default_value_t = 8080)] port: u16,
    #[arg(short, long)] browser: bool,
    #[arg(short, long, default_value = "http://chii.in")] url: String,
    /// 使用 Chrome（可选指定路径）
    #[arg(long, num_args = 0..=1, default_missing_value = "")] chrome: Option<Option<String>>,
    /// 使用 Chromium（可选指定路径）
    #[arg(long, num_args = 0..=1, default_missing_value = "")] chromium: Option<Option<String>>,
    /// 使用 Edge（可选指定路径）
    #[arg(long, num_args = 0..=1, default_missing_value = "")] edge: Option<Option<String>>,
    /// 使用 Firefox（可选指定路径）
    #[arg(long, num_args = 0..=1, default_missing_value = "")] firefox: Option<Option<String>>,
    /// DoH URL or plain DNS IP
    #[arg(long, default_value = "https://doh.pub/dns-query")] dns: String,
    /// 自定义 hosts 文件路径（标准格式：IP domain）
    #[arg(long)] hosts: Option<String>,
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
    hosts: std::collections::HashMap<String, std::net::Ipv4Addr>,
}
impl EchCache {
    fn new(dns: String, hosts: std::collections::HashMap<String, std::net::Ipv4Addr>) -> Self {
        Self { config: Mutex::new(None), ips: Mutex::new(std::collections::HashMap::new()), dns, hosts }
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
        if let Some(ip) = self.hosts.get(host) { println!("[hosts] {host} → {ip}"); return Ok(*ip); }
        if let Some(ip) = self.ips.lock().get(host) { return Ok(*ip); }
        let ip = match self.resolve_via_ech(host) {
            Ok(ip) => { println!("[DNS] {host} → {ip} (ECH)"); ip }
            Err(e) => { eprintln!("[DNS] ECH: {e}"); match self.resolve_host(host) {
                Ok(ip) => { println!("[DNS] {host} → {ip} ({})", self.dns); ip }
                Err(e2) => { eprintln!("[DNS] DoH: {e2}"); return self.fallback_or_err(host); }
            }}
        };
        // If DNS returned a non-Cloudflare IP for a target domain, it's likely poisoned — use hosts IP
        if !is_cloudflare_ip(ip) && is_target(host) {
            if let Some(&hosts_ip) = self.hosts.get(host) {
                eprintln!("[DNS] {host} → {ip} (poisoned! using hosts {hosts_ip})");
                self.ips.lock().insert(host.to_string(), hosts_ip);
                return Ok(hosts_ip);
            }
        }
        self.ips.lock().insert(host.to_string(), ip);
        Ok(ip)
    }
    fn fallback_or_err(&self, host: &str) -> io::Result<std::net::Ipv4Addr> {
        if let Some(&ip) = self.hosts.get(host) {
            println!("[DNS] {host} → {ip} (hosts fallback)");
            self.ips.lock().insert(host.to_string(), ip);
            return Ok(ip);
        }
        // Not a known target — try system DNS as last resort
        let ip = system_dns(host)?;
        println!("[DNS] {host} → {ip} (system)");
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
fn system_dns(host: &str) -> io::Result<std::net::Ipv4Addr> {
    for server in &["119.29.29.29", "223.5.5.5"] {
        if let Ok(ip) = resolve_plain_dns(server, host) { return Ok(ip); }
    }
    // Last resort: OS resolver
    format!("{host}:443").to_socket_addrs()?.find(|a| a.is_ipv4()).map(|a| match a.ip() { std::net::IpAddr::V4(v) => v, _ => unreachable!() }).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
}
#[cfg(has_ech)]
fn grease_ech(ip: std::net::Ipv4Addr) -> io::Result<Vec<u8>> {
    let h = std::ffi::CString::new(ip.to_string()).unwrap(); let s = std::ffi::CString::new(OUTER_SNI).unwrap();
    let (mut c, mut l): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    let r = unsafe { ech_get_retry_config(h.as_ptr(), 443, s.as_ptr(), &mut c, &mut l) };
    if r == 1 && !c.is_null() && l > 0 { let d = unsafe { std::slice::from_raw_parts(c, l).to_vec() }; unsafe { ech_free(c as *mut _) }; Ok(d) }
    else { Err(io::Error::new(io::ErrorKind::Other, "GREASE failed")) }
}
#[cfg(no_ech)]
fn grease_ech(_ip: std::net::Ipv4Addr) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "ECH not available: build with OpenSSL 4.0-dev for ECH support"))
}

// ============================= ECH backend ==================================

static INIT: std::sync::Once = std::sync::Once::new();
#[cfg(has_ech)]
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
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))?; tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let st = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let s = unsafe { ffi::SSL_ech_get1_status(st.ssl().as_ptr(), std::ptr::null_mut(), std::ptr::null_mut()) };
    println!("[ECH] {host} → {ip} status={s}");
    Ok(st)
}
#[cfg(no_ech)]
fn connect_ech(_host: &str, _ip: std::net::Ipv4Addr, _ecl: &[u8]) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "ECH not available"))
}
/// Direct TLS connection (no ECH). If `connect_ip` is given, connect to that IP directly.
fn connect_direct(host: &str, connect_ip: Option<std::net::Ipv4Addr>) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    INIT.call_once(|| openssl::init());
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build();
    let ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let host_c = std::ffi::CString::new(host).unwrap();
    unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), host_c.as_ptr() as *mut _) };
    let addr = match connect_ip { Some(ip) => format!("{ip}:443"), None => format!("{host}:443") };
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    let st = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    println!("[TLS] {host} → {addr} (direct)");
    Ok(st)
}

fn open_backend(host: &str, cache: &EchCache) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    let ip = cache.get_ip(host)?;
    if is_cloudflare_ip(ip) {
        if let Ok(ecl) = cache.get_ech() {
            match connect_ech(host, ip, &ecl) {
                Ok(s) => return Ok(s),
                Err(e) => { eprintln!("[ECH] {host} → {ip}: {e}"); }
            }
            cache.invalidate();
        }
    }
    // Direct TLS — pass IP if it came from hosts file so we bypass DNS
    let connect_ip = cache.hosts.get(host).copied();
    connect_direct(host, connect_ip)
}

fn is_cloudflare_ip(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    // 104.16.0.0/12, 172.64.0.0/13, 162.158.0.0/15, 188.114.96.0/20,
    // 190.93.240.0/20, 197.234.240.0/22, 198.41.128.0/17, 131.0.72.0/22,
    // 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22
    (o[0] == 104 && o[1] >= 16 && o[1] <= 31)
        || (o[0] == 172 && o[1] >= 64 && o[1] <= 71)
        || (o[0] == 162 && o[1] == 158)
        || (o[0] == 188 && o[1] == 114)
        || (o[0] == 190 && o[1] == 93)
        || (o[0] == 197 && o[1] == 234)
        || (o[0] == 198 && o[1] == 41)
        || (o[0] == 131 && o[1] == 0)
        || (o[0] == 103 && o[1] == 21 && o[2] >= 244 && o[2] <= 247)
        || (o[0] == 103 && o[1] == 22 && o[2] >= 200 && o[2] <= 203)
        || (o[0] == 103 && o[1] == 31 && o[2] >= 4 && o[2] <= 7)
}

fn handle_connect(client: &mut TcpStream, host: &str, cache: &EchCache, ps: &str, ca: &MitmCa) {
    if is_target(host) {
        handle_mitm(client, host, cache, ps, ca);
    } else {
        handle_tunnel(client, host, cache, ps);
    }
}

/// Raw TCP tunnel — relay bytes between browser and remote server without decryption.
fn handle_tunnel(client: &mut TcpStream, host: &str, cache: &EchCache, ps: &str) {
    let connect_addr = cache.hosts.get(host).map(|ip| format!("{ip}:443")).unwrap_or_else(|| format!("{host}:443"));
    let mut remote = match TcpStream::connect(&connect_addr) {
        Ok(s) => s,
        Err(e) => { eprintln!("[{ps}] tunnel {host}: {e}"); return; }
    };
    remote.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();
    remote.set_write_timeout(Some(std::time::Duration::from_secs(60))).ok();
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let _ = client.flush();
    println!("[{ps}] TUNNEL {host} → {connect_addr}");

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
#[derive(Clone, Copy, Debug)]
enum BrowserKind { Chrome, Chromium, Edge, Firefox }
impl BrowserKind {
    fn name(self) -> &'static str { match self { Self::Chrome => "chrome", Self::Chromium => "chromium", Self::Edge => "edge", Self::Firefox => "firefox" } }
    fn is_chromium(self) -> bool { matches!(self, Self::Chrome | Self::Chromium | Self::Edge) }
}

fn find_browser(kind: BrowserKind) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => &["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"],
            BrowserKind::Chromium => &["C:/Program Files/Chromium/Application/chrome.exe", "C:/Program Files (x86)/Chromium/Application/chrome.exe"],
            BrowserKind::Edge => &["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "C:/Program Files/Microsoft/Edge/Application/msedge.exe"],
            BrowserKind::Firefox => &["C:/Program Files/Mozilla Firefox/firefox.exe", "C:/Program Files (x86)/Mozilla Firefox/firefox.exe"],
        };
        for c in candidates { if std::path::Path::new(c).exists() { return Some(c.to_string()); } }
    }
    #[cfg(target_os = "linux")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => &["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
            BrowserKind::Chromium => &["/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"],
            BrowserKind::Edge => &["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"],
            BrowserKind::Firefox => &["/usr/bin/firefox", "/usr/bin/firefox-esr"],
        };
        for c in candidates { if std::path::Path::new(c).exists() { return Some(c.to_string()); } }
    }
    #[cfg(target_os = "macos")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => &["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
            BrowserKind::Chromium => &["/Applications/Chromium.app/Contents/MacOS/Chromium"],
            BrowserKind::Edge => &["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
            BrowserKind::Firefox => &["/Applications/Firefox.app/Contents/MacOS/firefox"],
        };
        for c in candidates { if std::path::Path::new(c).exists() { return Some(c.to_string()); } }
    }
    let names: &[&str] = match kind {
        BrowserKind::Chrome => &["google-chrome", "chrome"],
        BrowserKind::Chromium => &["chromium", "chromium-browser"],
        BrowserKind::Edge => &["microsoft-edge", "msedge"],
        BrowserKind::Firefox => &["firefox", "firefox-esr"],
    };
    for n in names { if let Some(p) = which::which(n).ok() { return Some(p.display().to_string()); } }
    None
}

/// Auto-detect browser with priority: chrome > chromium > edge > firefox
fn auto_detect_browser() -> Option<(BrowserKind, String)> {
    for kind in [BrowserKind::Chrome, BrowserKind::Chromium, BrowserKind::Edge, BrowserKind::Firefox] {
        if let Some(path) = find_browser(kind) { return Some((kind, path)); }
    }
    None
}

fn launch_browser(kind: BrowserKind, exe: &str, proxy: &str, url: &str) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let profile = std::env::temp_dir().join(format!("bangumi-proxy-{ts}"));
    let profile_s = profile.display().to_string();
    println!("[browser] {} proxy=http://{proxy} url={url}", kind.name());
    println!("[browser] exe={exe}");
    println!("[browser] profile={profile_s}\n");
    if kind.is_chromium() {
        match std::process::Command::new(exe).args([
            format!("--proxy-server=http://{proxy}"),
            "--remote-debugging-port=9222".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            format!("--user-data-dir={profile_s}"),
            "--ignore-certificate-errors".into(),
            url.into(),
        ]).spawn() {
            Ok(_) => {}
            Err(e) => eprintln!("[browser] failed to launch {}: {e}", kind.name()),
        }
    } else {
        // Firefox: create profile with proxy prefs
        // prefs.js is the primary config file Firefox reads on startup
        let _ = std::fs::create_dir_all(&profile);
        let _ = std::fs::write(profile.join("prefs.js"), format!(
            "user_pref(\"network.proxy.type\", 1);\n\
             user_pref(\"network.proxy.http\", \"127.0.0.1\");\n\
             user_pref(\"network.proxy.http_port\", {port});\n\
             user_pref(\"network.proxy.ssl\", \"127.0.0.1\");\n\
             user_pref(\"network.proxy.ssl_port\", {port});\n\
             user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
             user_pref(\"security.enterprise_roots.enabled\", true);\n\
             user_pref(\"security.OCSP.enabled\", 0);\n\
             user_pref(\"security.cert_pinning.enforcement_level\", 0);\n",
            port = proxy.split(':').nth(1).unwrap_or("8080")
        ));
        // Firefox: --no-remote avoids existing instances, CREATE_NEW_CONSOLE for Windows
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "--no-remote",
            "--profile",
            profile_s.as_str(),
            url,
        ]);
        #[cfg(target_os = "windows")]
        { use std::os::windows::process::CommandExt; cmd.creation_flags(0x00000010); } // CREATE_NEW_CONSOLE
        match cmd.spawn() {
            Ok(_) => {}
            Err(e) => eprintln!("[browser] failed to launch firefox: {e}"),
        }
    }
}
// ============================= main =========================================

fn main() -> io::Result<()> {
    let args = Args::parse();
    let addr = format!("127.0.0.1:{}", args.port);
    let ca = Arc::new(MitmCa::load_or_generate());
    let hosts = match &args.hosts { Some(path) => parse_hosts(path), None => std::collections::HashMap::new() };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  bangumi-proxy — HTTP/HTTPS + ECH 绕过 GFW                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  代理: http://{addr:<44}║");
    println!("║  站点: chii.in / lain.bgm.tv / bgm.tv / next.bgm.tv       ║");
    println!("║  DNS:  {:<52} ║", args.dns);
    println!("║  hosts:{:<52} ║", args.hosts.as_deref().unwrap_or("(none)"));
    println!("║  MITM: 自签 CA，支持 HTTPS                                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let cache = Arc::new(EchCache::new(args.dns.clone(), hosts));
    let listener = TcpListener::bind(&addr)?;
    println!("[proxy] Listening on {addr}\n");

    // Resolve browser launch: specific flag > -b auto-detect
    let browser_req: Option<(BrowserKind, Option<String>)> = 
        args.chrome.clone().map(|p| (BrowserKind::Chrome, p.filter(|s| !s.is_empty())))
        .or_else(|| args.chromium.clone().map(|p| (BrowserKind::Chromium, p.filter(|s| !s.is_empty()))))
        .or_else(|| args.edge.clone().map(|p| (BrowserKind::Edge, p.filter(|s| !s.is_empty()))))
        .or_else(|| args.firefox.clone().map(|p| (BrowserKind::Firefox, p.filter(|s| !s.is_empty()))));
    
    if let Some((kind, explicit_path)) = browser_req {
        let exe = explicit_path.or_else(|| find_browser(kind)).unwrap_or_else(|| {
            eprintln!("[browser] {} not found", kind.name());
            std::process::exit(1);
        });
        launch_browser(kind, &exe, &addr, &args.url);
    } else if args.browser {
        if let Some((kind, exe)) = auto_detect_browser() {
            launch_browser(kind, &exe, &addr, &args.url);
        } else {
            eprintln!("[browser] No supported browser found");
            std::process::exit(1);
        }
    } else {
        println!("Tip: use -b to auto-launch browser, or --chrome/--edge/--firefox\n");
    }

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let (cache, ca) = (Arc::clone(&cache), Arc::clone(&ca));
            thread::spawn(move || handle_client(client, cache, ca));
        }
    }
    Ok(())
}
