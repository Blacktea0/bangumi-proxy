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

pub fn parse_a(json: &str) -> Option<Ipv4Addr> {
    let answer = json.find("\"Answer\"")?;
    let data = json[answer..].find("\"data\":\"")?;
    let addr = &json[answer + data + 8..];
    let end = addr.find('"')?;
    addr[..end].parse().ok()
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

pub fn system_dns(host: &str) -> io::Result<Ipv4Addr> {
    for server in &["119.29.29.29", "223.5.5.5"] {
        if let Ok(ip) = resolve_plain_dns(server, host) {
            return Ok(ip);
        }
    }

    format!("{host}:443")
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A"))
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
