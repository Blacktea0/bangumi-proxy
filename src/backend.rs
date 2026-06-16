use std::io;
use std::net::{Ipv4Addr, TcpStream};

use foreign_types_shared::ForeignType;

use crate::ech::{connect_ech, init_openssl, EchCache};
use crate::targets::is_cloudflare_ip;

pub fn open_backend(
    host: &str,
    cache: &EchCache,
) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    let max_retries = 2;
    let mut last_err = None;

    for attempt in 0..max_retries {
        let ip = match cache.get_ip(host) {
            Ok(ip) => ip,
            Err(err) => {
                eprintln!(
                    "[backend] {host} resolve failed (attempt {}): {err}",
                    attempt + 1
                );
                last_err = Some(err);
                cache.invalidate_ip(host);
                continue;
            }
        };

        // try ECH first for CF IPs
        if is_cloudflare_ip(ip) {
            if let Ok(ecl) = cache.get_ech() {
                match connect_ech(host, ip, &ecl) {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        eprintln!("[ECH] {host} -> {ip}: {err} (attempt {})", attempt + 1);
                    }
                }
                cache.invalidate();
            }
        }

        // fall back to direct TLS
        let connect_ip = cache.hosts.get(host).copied();
        match connect_direct(host, connect_ip) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                eprintln!(
                    "[TLS] {host} direct failed (attempt {}): {err}",
                    attempt + 1
                );
                last_err = Some(err);
                cache.invalidate_ip(host);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "all connection attempts failed")))
}

/// Direct TLS connection (no ECH). If `connect_ip` is given, connect to that IP directly.
fn connect_direct(
    host: &str,
    connect_ip: Option<Ipv4Addr>,
) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    init_openssl();
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    ctx.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ctx = ctx.build();
    let ssl = openssl::ssl::Ssl::new(&ctx)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let host_c = std::ffi::CString::new(host).unwrap();
    unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), host_c.as_ptr() as *mut _) };

    let addr = match connect_ip {
        Some(ip) => format!("{ip}:443"),
        None => format!("{host}:443"),
    };
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    let stream = ssl
        .connect(tcp)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    println!("[TLS] {host} -> {addr} (direct)");
    Ok(stream)
}
