use std::net::Ipv4Addr;

pub const TARGETS: &[&str] = &[
    "chii.in",
    "lain.bgm.tv",
    "bgm.tv",
    "next.bgm.tv",
    "api.bgm.tv",
];

const CLOUDFLARE_IPV4_CIDRS: &[(u32, u8)] = &[
    (ipv4_as_u32(173, 245, 48, 0), 20),
    (ipv4_as_u32(103, 21, 244, 0), 22),
    (ipv4_as_u32(103, 22, 200, 0), 22),
    (ipv4_as_u32(103, 31, 4, 0), 22),
    (ipv4_as_u32(141, 101, 64, 0), 18),
    (ipv4_as_u32(108, 162, 192, 0), 18),
    (ipv4_as_u32(190, 93, 240, 0), 20),
    (ipv4_as_u32(188, 114, 96, 0), 20),
    (ipv4_as_u32(197, 234, 240, 0), 22),
    (ipv4_as_u32(198, 41, 128, 0), 17),
    (ipv4_as_u32(162, 158, 0, 0), 15),
    (ipv4_as_u32(104, 16, 0, 0), 13),
    (ipv4_as_u32(104, 24, 0, 0), 14),
    (ipv4_as_u32(172, 64, 0, 0), 13),
    (ipv4_as_u32(131, 0, 72, 0), 22),
];

const fn ipv4_as_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32
}

pub fn is_target(host: &str) -> bool {
    TARGETS
        .iter()
        .any(|&target| host == target || host.ends_with(&format!(".{target}")))
}

pub fn is_cloudflare_ip(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);

    CLOUDFLARE_IPV4_CIDRS
        .iter()
        .any(|&(network, prefix)| ipv4_in_cidr(ip, network, prefix))
}

fn ipv4_in_cidr(ip: u32, network: u32, prefix: u8) -> bool {
    let mask = u32::MAX << (32 - prefix);
    (ip & mask) == (network & mask)
}

#[cfg(test)]
mod tests {
    use super::is_cloudflare_ip;
    use std::net::Ipv4Addr;

    #[test]
    fn matches_cloudflare_ipv4_ranges() {
        for ip in [
            Ipv4Addr::new(173, 245, 48, 0),
            Ipv4Addr::new(103, 21, 244, 1),
            Ipv4Addr::new(103, 22, 200, 1),
            Ipv4Addr::new(103, 31, 4, 1),
            Ipv4Addr::new(141, 101, 64, 1),
            Ipv4Addr::new(108, 162, 192, 1),
            Ipv4Addr::new(190, 93, 240, 1),
            Ipv4Addr::new(188, 114, 96, 1),
            Ipv4Addr::new(197, 234, 240, 1),
            Ipv4Addr::new(198, 41, 128, 1),
            Ipv4Addr::new(162, 159, 255, 255),
            Ipv4Addr::new(104, 27, 255, 255),
            Ipv4Addr::new(172, 71, 255, 255),
            Ipv4Addr::new(131, 0, 75, 255),
        ] {
            assert!(is_cloudflare_ip(ip), "{ip} should match");
        }
    }

    #[test]
    fn rejects_ips_outside_cloudflare_ipv4_ranges() {
        for ip in [
            Ipv4Addr::new(173, 245, 47, 255),
            Ipv4Addr::new(141, 101, 128, 0),
            Ipv4Addr::new(108, 162, 191, 255),
            Ipv4Addr::new(188, 114, 112, 0),
            Ipv4Addr::new(198, 41, 127, 255),
            Ipv4Addr::new(104, 28, 0, 0),
            Ipv4Addr::new(172, 72, 0, 0),
            Ipv4Addr::new(131, 0, 76, 0),
        ] {
            assert!(!is_cloudflare_ip(ip), "{ip} should not match");
        }
    }
}
