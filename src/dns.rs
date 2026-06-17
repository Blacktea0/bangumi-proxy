use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};

pub fn doh_json(host: &str, path: &str) -> io::Result<String> {
    let tcp = TcpStream::connect(format!("{host}:443"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut stream = tls_skip()
        .connect(host, tcp)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    stream.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no hdr"))?;
    String::from_utf8(buf[header_end + 4..].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))
}

pub fn parse_a_records(json: &str) -> Vec<Ipv4Addr> {
    let Some(answer) = json.find("\"Answer\"") else {
        return Vec::new();
    };

    let mut ips = Vec::new();
    let mut rest = &json[answer..];
    while let Some(data) = rest.find("\"data\":\"") {
        let addr = &rest[data + 8..];
        let Some(end) = addr.find('"') else {
            break;
        };
        if let Ok(ip) = addr[..end].parse::<Ipv4Addr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        rest = &addr[end..];
    }
    ips
}

pub fn resolve_plain_dns(server: &str, host: &str) -> io::Result<Ipv4Addr> {
    let txid: u16 = 0x1234;
    let mut pkt = Vec::with_capacity(512);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0, 1, 0, 1]);

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(&pkt, format!("{server}:53"))?;
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf)?;
    let response = &buf[..n];
    if response.len() < 12 || u16::from_be_bytes([response[0], response[1]]) != txid {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS"));
    }

    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut pos = skip_name(response, 12)? + 4;
    for _ in 0..answers {
        pos = skip_name(response, pos)?;
        if pos + 10 > response.len() {
            break;
        }

        let record_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let record_len = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if record_type == 1 && record_len == 4 && pos + 4 <= response.len() {
            return Ok(Ipv4Addr::new(
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            ));
        }
        pos += record_len;
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "no A"))
}

pub fn resolve_multi_no_fallback(host: &str, servers: &[String]) -> io::Result<Vec<Ipv4Addr>> {
    let mut last_err = None;
    for server in servers {
        if is_doh(server) {
            match resolve_doh_server_multi(server, host) {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => last_err = Some(io::Error::new(io::ErrorKind::NotFound, "no A")),
                Err(err) => last_err = Some(err),
            }
        } else if is_plain_dns(server) {
            match resolve_plain_server(server, host) {
                Ok(ip) => return Ok(vec![ip]),
                Err(err) => last_err = Some(err),
            }
        } else {
            // unknown format — try both
            match resolve_doh_server_multi(server, host) {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => {}
                Err(_) => {}
            }
            match resolve_plain_server(server, host) {
                Ok(ip) => return Ok(vec![ip]),
                Err(err) => last_err = Some(err),
            }
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A")))
}

fn is_doh(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn is_plain_dns(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok() || s.contains(':')
}

fn resolve_doh_server_multi(server: &str, host: &str) -> io::Result<Vec<Ipv4Addr>> {
    let base = server
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let (doh_host, path) = base
        .split_once('/')
        .map(|(host, path)| (host, format!("/{path}")))
        .unwrap_or((base, "/dns-query".into()));
    let json = doh_json(doh_host, &format!("{path}?name={host}&type=A"))?;
    let ips = parse_a_records(&json);
    if ips.is_empty() {
        Err(io::Error::new(io::ErrorKind::NotFound, "no A"))
    } else {
        Ok(ips)
    }
}

fn resolve_plain_server(server: &str, host: &str) -> io::Result<Ipv4Addr> {
    let addr = if server.parse::<Ipv4Addr>().is_ok() {
        server.to_string()
    } else {
        format!("{}:53", server)
            .to_socket_addrs()?
            .find(|addr| addr.is_ipv4())
            .map(|addr| addr.ip().to_string())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "can't resolve DNS server"))?
    };
    resolve_plain_dns(&addr, host)
}

fn tls_skip() -> openssl::ssl::SslConnector {
    let mut builder =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    builder.build()
}

fn skip_name(data: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "overflow"));
        }

        let byte = data[pos];
        if byte == 0 {
            return Ok(pos + 1);
        }
        if byte & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + byte as usize;
    }
}
