use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};

use foreign_types_shared::ForeignType;
use foreign_types_shared::ForeignTypeRef;
use parking_lot::Mutex;

use crate::dns::{parse_a_records, resolve_multi_no_fallback};
use crate::targets::{is_cloudflare_ip, is_target};

const OUTER_SNI: &str = "cloudflare-ech.com";

pub const CF_DOH_IPS: &[Ipv4Addr] = &[
    Ipv4Addr::new(104, 16, 248, 249),
    Ipv4Addr::new(104, 16, 249, 249),
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
];
pub const CF_DOH_HOST: &str = "cloudflare-dns.com";

static INIT: std::sync::Once = std::sync::Once::new();

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
    ips: Mutex<HashMap<String, Vec<Ipv4Addr>>>,
    dns_servers: Vec<String>,
    cf_ips: Mutex<Option<Vec<Ipv4Addr>>>,
    pub hosts: HashMap<String, Ipv4Addr>,
}

impl EchCache {
    pub fn new(dns_servers: Vec<String>, hosts: HashMap<String, Ipv4Addr>) -> Self {
        Self {
            config: Mutex::new(None),
            ips: Mutex::new(HashMap::new()),
            dns_servers,
            cf_ips: Mutex::new(None),
            hosts,
        }
    }

    pub fn get_ech(&self) -> io::Result<Vec<u8>> {
        if let Some(config) = &*self.config.lock() {
            return Ok(config.clone());
        }

        // Try each resolved CF DoH IP until GREASE succeeds.
        for ip in self.cloudflare_doh_ips()? {
            match grease_ech(ip) {
                Ok(config) => {
                    println!("[ECH] {CF_DOH_HOST} -> {ip}, GREASE {} bytes", config.len());
                    *self.config.lock() = Some(config.clone());
                    return Ok(config);
                }
                Err(err) => {
                    eprintln!("[ECH] {CF_DOH_HOST} -> {ip}: {err}");
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "all CF DoH IPs failed for GREASE",
        ))
    }

    pub fn get_target_ips(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        if !is_target(host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ECH DNS is only for target hosts",
            ));
        }

        if let Some(ips) = self.ips.lock().get(host) {
            return Ok(ips.clone());
        }

        let mut ips = self.resolve_via_ech_multi(host)?;
        let original_len = ips.len();
        ips.retain(|ip| is_cloudflare_ip(*ip));
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "target resolved to no Cloudflare IPs",
            ));
        }
        if ips.len() != original_len {
            eprintln!("[DNS] {host}: ignored non-Cloudflare A records");
        }

        println!("[DNS] {host} -> {:?} (ECH)", ips);
        self.ips.lock().insert(host.to_string(), ips.clone());
        Ok(ips)
    }

    pub fn invalidate(&self) {
        self.config.lock().take();
    }

    pub fn invalidate_ips(&self, host: &str) {
        self.ips.lock().remove(host);
    }

    fn cloudflare_doh_ips(&self) -> io::Result<Vec<Ipv4Addr>> {
        if let Some(ips) = &*self.cf_ips.lock() {
            return Ok(ips.clone());
        }

        let mut ips = match resolve_multi_no_fallback(CF_DOH_HOST, &self.dns_servers) {
            Ok(ips) => ips,
            Err(err) => {
                eprintln!("[DNS] {CF_DOH_HOST} bootstrap failed: {err}; using built-in IPs");
                Vec::new()
            }
        };
        let original_len = ips.len();
        ips.retain(|ip| is_cloudflare_ip(*ip));
        if ips.is_empty() {
            ips = CF_DOH_IPS.to_vec();
            println!("[DNS] {CF_DOH_HOST} -> {:?} (built-in)", ips);
        } else {
            if ips.len() != original_len {
                eprintln!("[DNS] {CF_DOH_HOST}: ignored non-Cloudflare A records");
            }
            println!("[DNS] {CF_DOH_HOST} -> {:?} (bootstrap)", ips);
        }
        *self.cf_ips.lock() = Some(ips.clone());
        Ok(ips)
    }

    fn resolve_via_ech_multi(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        let ecl = self.get_ech()?;

        let doh_query = |ip: Ipv4Addr| -> io::Result<Vec<Ipv4Addr>> {
            let mut backend = connect_ech(CF_DOH_HOST, ip, &ecl)?;
            backend.write_all(
                format!("GET /dns-query?name={host}&type=A HTTP/1.1\r\nHost: {CF_DOH_HOST}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )?;
            backend.flush()?;

            let mut buf = Vec::new();
            backend.read_to_end(&mut buf)?;
            let header_end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
            let ips = parse_a_records(&String::from_utf8_lossy(&buf[header_end + 4..]));
            if ips.is_empty() {
                Err(io::Error::new(io::ErrorKind::NotFound, "no A"))
            } else {
                Ok(ips)
            }
        };

        // Try each resolved CF DoH IP. Do not fall back to non-ECH DNS.
        let mut last_err = None;
        for cf_ip in self.cloudflare_doh_ips()? {
            match doh_query(cf_ip) {
                Ok(ips) => return Ok(ips),
                Err(err) => {
                    eprintln!("[ECH] DNS via {cf_ip}: {err}");
                    last_err = Some(err);
                }
            }
        }

        // all CF IPs failed — invalidate ECH config for next retry
        self.invalidate();
        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "all CF IPs failed")))
    }
}

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

    let tcp = TcpStream::connect_timeout(
        &SocketAddrV4::new(ip, 443).into(),
        std::time::Duration::from_secs(10),
    )?;
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

pub fn init_openssl() {
    INIT.call_once(openssl::init);
}
