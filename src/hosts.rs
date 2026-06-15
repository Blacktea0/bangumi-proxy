use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Parse a standard hosts file (IP domain1 [domain2 ...]).
pub fn parse_hosts(path: &str) -> HashMap<String, Ipv4Addr> {
    let mut map = HashMap::new();
    let data = match std::fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("[hosts] {path}: {err}");
            return map;
        }
    };

    for line in data.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let ip = match parts.next().and_then(|s| s.parse().ok()) {
            Some(ip) => ip,
            None => continue,
        };

        for domain in parts {
            map.insert(domain.to_lowercase(), ip);
        }
    }

    map
}
