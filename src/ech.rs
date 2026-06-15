use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};

use foreign_types_shared::ForeignType;
#[cfg(has_ech)]
use foreign_types_shared::ForeignTypeRef;
use parking_lot::Mutex;

use crate::dns::{doh_json, parse_a, resolve_plain_dns, system_dns};
use crate::targets::{is_cloudflare_ip, is_target};

#[cfg(has_ech)]
const OUTER_SNI: &str = "cloudflare-ech.com";
pub const CF_DOH_IP: Ipv4Addr = Ipv4Addr::new(104, 16, 248, 249);
pub const CF_DOH_HOST: &str = "cloudflare-dns.com";

static INIT: std::sync::Once = std::sync::Once::new();

#[cfg(has_ech)]
unsafe extern "C" {
    fn ech_get_retry_config(
        host: *const std::os::raw::c_char,
        port: std::os::raw::c_int,
        outer_sni: *const std::os::raw::c_char,
        out_cfg: *mut *mut u8,
        out_len: *mut usize,
    ) -> std::os::raw::c_int;
    fn ech_free(p: *mut std::os::raw::c_void);
}

#[cfg(has_ech)]
mod ffi {
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        pub fn SSL_set1_ech_config_list(
            s: *mut openssl_sys::SSL,
            ecl: *const u8,
            len: usize,
        ) -> c_int;
        pub fn SSL_ech_set1_server_names(
            s: *mut openssl_sys::SSL,
            inner: *const c_char,
            outer: *const c_char,
            no_outer: c_int,
        ) -> c_int;
        pub fn SSL_ech_get1_status(
            s: *mut openssl_sys::SSL,
            inner: *mut *mut c_char,
            outer: *mut *mut c_char,
        ) -> c_int;
    }
}

pub struct EchCache {
    config: Mutex<Option<Vec<u8>>>,
    ips: Mutex<HashMap<String, Ipv4Addr>>,
    dns: String,
    pub hosts: HashMap<String, Ipv4Addr>,
}

impl EchCache {
    pub fn new(dns: String, hosts: HashMap<String, Ipv4Addr>) -> Self {
        Self {
            config: Mutex::new(None),
            ips: Mutex::new(HashMap::new()),
            dns,
            hosts,
        }
    }

    pub fn get_ech(&self) -> io::Result<Vec<u8>> {
        if let Some(config) = &*self.config.lock() {
            return Ok(config.clone());
        }

        let ip = self.resolve_host(CF_DOH_HOST)?;
        println!("[ECH] {CF_DOH_HOST} -> {ip}, GREASE...");
        let config = grease_ech(ip)?;
        println!("[ECH] {} bytes", config.len());
        *self.config.lock() = Some(config.clone());
        Ok(config)
    }

    pub fn get_ip(&self, host: &str) -> io::Result<Ipv4Addr> {
        if let Some(ip) = self.hosts.get(host) {
            println!("[hosts] {host} -> {ip}");
            return Ok(*ip);
        }
        if let Some(ip) = self.ips.lock().get(host) {
            return Ok(*ip);
        }

        let ip = match self.resolve_via_ech(host) {
            Ok(ip) => {
                println!("[DNS] {host} -> {ip} (ECH)");
                ip
            }
            Err(err) => {
                eprintln!("[DNS] ECH: {err}");
                match self.resolve_host(host) {
                    Ok(ip) => {
                        println!("[DNS] {host} -> {ip} ({})", self.dns);
                        ip
                    }
                    Err(doh_err) => {
                        eprintln!("[DNS] DoH: {doh_err}");
                        return self.fallback_or_err(host);
                    }
                }
            }
        };

        if !is_cloudflare_ip(ip) && is_target(host) {
            if let Some(&hosts_ip) = self.hosts.get(host) {
                eprintln!("[DNS] {host} -> {ip} (poisoned! using hosts {hosts_ip})");
                self.ips.lock().insert(host.to_string(), hosts_ip);
                return Ok(hosts_ip);
            }
        }

        self.ips.lock().insert(host.to_string(), ip);
        Ok(ip)
    }

    pub fn invalidate(&self) {
        self.config.lock().take();
    }

    fn fallback_or_err(&self, host: &str) -> io::Result<Ipv4Addr> {
        if let Some(&ip) = self.hosts.get(host) {
            println!("[DNS] {host} -> {ip} (hosts fallback)");
            self.ips.lock().insert(host.to_string(), ip);
            return Ok(ip);
        }

        let ip = system_dns(host)?;
        println!("[DNS] {host} -> {ip} (system)");
        self.ips.lock().insert(host.to_string(), ip);
        Ok(ip)
    }

    fn resolve_host(&self, host: &str) -> io::Result<Ipv4Addr> {
        if self.dns.starts_with("http") {
            let base = self
                .dns
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let (doh_host, path) = base
                .split_once('/')
                .map(|(host, path)| (host, format!("/{path}")))
                .unwrap_or((base, "/dns-query".into()));
            let json = doh_json(doh_host, &format!("{path}?name={host}&type=A"))?;
            parse_a(&json).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
        } else {
            let server = if self.dns.parse::<Ipv4Addr>().is_ok() {
                self.dns.clone()
            } else {
                format!("{}:53", self.dns)
                    .to_socket_addrs()?
                    .find(|addr| addr.is_ipv4())
                    .map(|addr| addr.ip().to_string())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "can't resolve DNS server")
                    })?
            };
            resolve_plain_dns(&server, host)
        }
    }

    fn resolve_via_ech(&self, host: &str) -> io::Result<Ipv4Addr> {
        let ecl = self.get_ech()?;
        let mut backend = connect_ech(CF_DOH_HOST, CF_DOH_IP, &ecl)?;
        backend.write_all(format!("GET /dns-query?name={host}&type=A HTTP/1.1\r\nHost: {CF_DOH_HOST}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n").as_bytes())?;
        backend.flush()?;

        let mut buf = Vec::new();
        backend.read_to_end(&mut buf)?;
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
        parse_a(&String::from_utf8_lossy(&buf[header_end + 4..]))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
    }
}

#[cfg(has_ech)]
fn grease_ech(ip: Ipv4Addr) -> io::Result<Vec<u8>> {
    let host = std::ffi::CString::new(ip.to_string()).unwrap();
    let outer_sni = std::ffi::CString::new(OUTER_SNI).unwrap();
    let (mut config, mut len): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    let result = unsafe {
        ech_get_retry_config(
            host.as_ptr(),
            443,
            outer_sni.as_ptr(),
            &mut config,
            &mut len,
        )
    };

    if result == 1 && !config.is_null() && len > 0 {
        let data = unsafe { std::slice::from_raw_parts(config, len).to_vec() };
        unsafe { ech_free(config as *mut _) };
        Ok(data)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "GREASE failed"))
    }
}

#[cfg(no_ech)]
fn grease_ech(_ip: Ipv4Addr) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ECH not available: build with OpenSSL 4.0-dev for ECH support",
    ))
}

#[cfg(has_ech)]
pub fn connect_ech(
    host: &str,
    ip: Ipv4Addr,
    ecl: &[u8],
) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    INIT.call_once(openssl::init);
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build();
    let ssl = openssl::ssl::Ssl::new(&ctx)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    if unsafe { ffi::SSL_set1_ech_config_list(ssl.as_ptr(), ecl.as_ptr(), ecl.len()) } != 1 {
        return Err(io::Error::new(io::ErrorKind::Other, "ech_config"));
    }

    let inner = std::ffi::CString::new(host).unwrap();
    let outer = std::ffi::CString::new(OUTER_SNI).unwrap();
    unsafe { ffi::SSL_ech_set1_server_names(ssl.as_ptr(), inner.as_ptr(), outer.as_ptr(), 0) };

    let tcp = TcpStream::connect(format!("{ip}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let stream = ssl
        .connect(tcp)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let status = unsafe {
        ffi::SSL_ech_get1_status(
            stream.ssl().as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    println!("[ECH] {host} -> {ip} status={status}");
    Ok(stream)
}

#[cfg(no_ech)]
pub fn connect_ech(
    _host: &str,
    _ip: Ipv4Addr,
    _ecl: &[u8],
) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ECH not available",
    ))
}

pub fn init_openssl() {
    INIT.call_once(openssl::init);
}
