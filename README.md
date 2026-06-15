# bangumi-proxy

A local HTTP/HTTPS proxy that unblocks access to [Bangumi](https://bgm.tv/) and related sites (`chii.in`, `lain.bgm.tv`, `next.bgm.tv`) using **ECH (Encrypted Client Hello)** to bypass SNI-based blocking.

## How It Works

1. Intercepts browser requests to Bangumi domains
2. Uses DNS-over-HTTPS (DoH) to resolve the real IP behind Cloudflare
3. Establishes a TLS connection with GREASE ECH, hiding the real SNI from censors
4. Proxies the traffic back to your browser transparently

For target domains, the proxy performs MITM decryption to modify responses when needed. Non-target traffic passes through as a plain TCP tunnel.

## Features

- **ECH Proxy** — GREASE ECH via OpenSSL 4.0 to bypass SNI filtering
- **DNS-over-HTTPS** — Bypasses DNS poisoning (Cloudflare DoH / custom)
- **MITM for Bangumi** — Transparently modifies responses for target domains
- **Custom Hosts** — Override DNS resolution with a standard hosts file
- **Auto Browser Launch** — Detects and launches Chrome/Edge/Firefox with proxy pre-configured
- **CA Certificate Management** — Auto-generates and installs MITM CA to system trust store
- **Self-Contained Builds** — Static binaries with no runtime dependencies

## Installation

### Download Pre-built Binaries

Grab the latest release from [GitHub Releases](https://github.com/Blacktea0/bangumi-proxy/releases).

| Platform | File |
|---|---|
| Linux x86_64 | `bangumi-proxy-*-linux-x86_64.tar.gz` |
| Windows x86_64 | `bangumi-proxy-*-windows-x86_64.zip` |
| macOS (Intel) | `bangumi-proxy-*-macos-x86_64.tar.gz` |
| macOS (Apple Silicon) | `bangumi-proxy-*-macos-aarch64.tar.gz` |

### Build from Source

Requires [Rust](https://rustup.rs/) (stable) and [Conan 2.x](https://conan.io/).

```bash
# Install Conan
pip install conan   # or: pipx install conan

# Install OpenSSL 4.0 via Conan
conan profile detect --force
# Linux/macOS:
conan install conan --build=missing -s build_type=Release
# Windows (static CRT to match Rust MSVC default):
conan install conan --build=missing -s build_type=Release -s compiler.runtime=static

# Set OpenSSL paths (Linux/macOS):
CONAN_PKG=$(find ~/.conan2/p -path "*/p/include/openssl/ech.h" 2>/dev/null | head -1 | sed 's|/include/openssl/ech.h||')
export OPENSSL_DIR=$CONAN_PKG
export OPENSSL_INCLUDE_DIR=$CONAN_PKG/include
export OPENSSL_LIB_DIR=$CONAN_PKG/lib
export OPENSSL_STATIC=1

# Build
cargo build --release
```

## Usage

```
bangumi-proxy [OPTIONS]

Options:
  -p, --port <PORT>        Listening port [default: 8080]
  -b, --browser            Launch browser with auto-configured proxy
  -u, --url <URL>          URL to open in browser [default: https://bgm.tv]
      --chrome [PATH]      Use Chrome (optional custom path)
      --chromium [PATH]    Use Chromium (optional custom path)
      --edge [PATH]        Use Edge (optional custom path)
      --firefox [PATH]     Use Firefox (optional custom path)
      --dns <DNS>          DoH URL or plain DNS IP [default: https://doh.pub/dns-query]
      --hosts <HOSTS>      Custom hosts file path (standard format: IP domain)
      --trust-ca           Install CA certificate to system trust store
```

### Quick Start

```bash
# Start proxy on default port 8080
bangumi-proxy

# Auto-detect browser and open Bangumi
bangumi-proxy -b

# Use a specific browser
bangumi-proxy --chrome -u https://bgm.tv

# First-time setup: install CA certificate
bangumi-proxy --trust-ca
```

### Manual Browser Configuration

If not using `-b`, configure your browser to use `http://127.0.0.1:8080` as the HTTP proxy.

## License

MIT
