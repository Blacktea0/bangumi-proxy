# bangumi-proxy

`bangumi-proxy` is a local HTTP/HTTPS proxy for accessing
[Bangumi](https://bgm.tv/) and related sites:

- `bgm.tv`
- `chii.in`
- `lain.bgm.tv`
- `next.bgm.tv`

It prefers **ECH (Encrypted Client Hello)** when connecting to Cloudflare
backends, which helps hide the real SNI in the TLS handshake and work around
SNI-based blocking. Point your browser's HTTP/HTTPS proxy to this program, or
use `-b` to launch a browser with the proxy already configured.

## Features

- **ECH proxying**: uses OpenSSL 4.0 ECH APIs when connecting to Cloudflare IPs
- **DNS-over-HTTPS**: supports DoH URLs and plain DNS server IPs
- **ECH DoH resolution**: resolves target A records through Cloudflare DoH over ECH first
- **Targeted MITM**: generates per-host certificates only for Bangumi target domains
- **Pass-through tunneling**: non-target CONNECT requests are relayed as raw TCP tunnels
- **Custom hosts**: supports standard hosts files for overriding target IPs
- **Browser launch**: auto-detects Chrome, Chromium, Edge, or Firefox and configures the proxy
- **Local CA management**: generates a local CA and can install it with `--trust-ca`

## How It Works

### Request Flow

When the browser accesses a target site, traffic follows this path:

```text
Browser
  -> 127.0.0.1:8080 (bangumi-proxy)
  -> DNS / hosts resolution
  -> ECH TLS or direct TLS to the remote server
  -> bidirectional relay between browser and server
```

The proxy listens on `127.0.0.1:<port>`. For each browser request, it first
checks the request type:

- Plain HTTP requests: parse `Host` and path, rebuild the request, and forward it
  through a backend TLS connection.
- HTTPS `CONNECT` requests: return `200 Connection Established`, then choose
  either local MITM or raw TCP tunneling based on the host.

### Target Host Matching

Target domains are defined in `src/targets.rs`:

```text
chii.in / lain.bgm.tv / bgm.tv / next.bgm.tv
```

These domains and their subdomains use the Bangumi-specific path. Other domains
are not decrypted or modified; they are forwarded as plain TCP tunnels to the
remote `:443` endpoint.

### DNS and Hosts Resolution

Target IPs are resolved in this order:

1. A custom hosts file from `--hosts`
2. Cloudflare DoH queried through an ECH TLS connection
3. DoH or plain DNS servers from `--dns`
4. Built-in fallback DNS / system resolution

If the resolved IP is in a Cloudflare range, the backend connection tries ECH
first. Otherwise, it uses a direct TLS connection. IPs and ECH config lists are
cached in memory and invalidated after connection failures.

### ECH Connections

ECH logic lives in `src/ech.rs` and `ech_helper.c`.

The proxy first performs a GREASE ECH handshake against Cloudflare DoH IPs and
extracts the retry config as an ECH config list. That config is cached and reused
for later backend connections. When connecting to a Bangumi backend, the proxy:

1. Uses the target host as the inner SNI
2. Uses `cloudflare-ech.com` as the outer SNI
3. Sets the ECH config list through OpenSSL 4.0
4. Connects to the resolved Cloudflare IP

The visible outer ClientHello contains the outer SNI, while the real target host
is placed in the encrypted inner ClientHello.

### HTTPS MITM and Local CA

For HTTPS `CONNECT` requests to target domains, the proxy performs local MITM:

1. Load or generate `ca.pem` and `ca-key.pem`
2. Generate a temporary certificate for the requested host
3. Establish TLS between the browser and the proxy using that certificate
4. Establish ECH TLS or direct TLS between the proxy and the remote server
5. Relay decrypted HTTP data between both TLS sessions

Because of this, the local CA must be trusted before HTTPS target sites can be
used without certificate warnings:

```bash
bangumi-proxy --trust-ca
```

When launching Chromium-based browsers with `-b`, the proxy uses an isolated
temporary profile and passes `--ignore-certificate-errors` for easier testing.
For regular use, trusting the local CA is still recommended.

### Fallback Behavior

Backend connections use limited retries:

- ECH failures invalidate the cached ECH config and try fetching it again
- DNS failures move on to the next resolver path
- If ECH cannot be used, the proxy falls back to direct TLS
- Hosts-file IPs are preferred for both resolution and connection fallback

## Installation

### Download Prebuilt Binaries

Download the package for your platform from
[GitHub Releases](https://github.com/Blacktea0/bangumi-proxy/releases).

| Platform | File |
| --- | --- |
| Linux x86_64 | `bangumi-proxy-*-linux-x86_64.tar.gz` |
| Windows x86_64 | `bangumi-proxy-*-windows-x86_64.zip` |
| macOS Intel | `bangumi-proxy-*-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `bangumi-proxy-*-macos-aarch64.tar.gz` |

### Build from Source

Requirements:

- [Rust](https://rustup.rs/) stable
- [Conan 2.x](https://conan.io/)
- A C compiler: MSVC on Windows, gcc or clang on Linux/macOS

```bash
# Install Conan
pip install conan
# or
pipx install conan

# Install OpenSSL 4.0
conan profile detect --force

# Linux/macOS
conan install conan --build=missing -s build_type=Release

# Windows: use static CRT to match Rust MSVC defaults
conan install conan --build=missing -s build_type=Release -s compiler.runtime=static
```

Set OpenSSL environment variables on Linux/macOS:

```bash
CONAN_PKG=$(find ~/.conan2/p -path "*/p/include/openssl/ech.h" 2>/dev/null | head -1 | sed 's|/include/openssl/ech.h||')
export OPENSSL_DIR=$CONAN_PKG
export OPENSSL_INCLUDE_DIR=$CONAN_PKG/include
export OPENSSL_LIB_DIR=$CONAN_PKG/lib
export OPENSSL_STATIC=1
```

Set OpenSSL environment variables in Windows PowerShell:

```powershell
$libFile = Get-ChildItem -Path "$env:USERPROFILE\.conan2\p" -Recurse -Filter "libssl.lib" -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "\\p\\lib\\" } | Select-Object -First 1
$CONAN_PKG = $libFile.Directory.Parent.FullName
$env:OPENSSL_DIR = $CONAN_PKG
$env:OPENSSL_INCLUDE_DIR = "$CONAN_PKG\include"
$env:OPENSSL_LIB_DIR = $libFile.DirectoryName
$env:OPENSSL_STATIC = "1"
```

Build:

```bash
cargo build --release
```

## Usage

```text
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
# Start the default proxy at 127.0.0.1:8080
bangumi-proxy

# Auto-detect a browser and open bgm.tv
bangumi-proxy -b

# Use a specific browser
bangumi-proxy --chrome -u https://bgm.tv
bangumi-proxy --edge -u https://bgm.tv
bangumi-proxy --firefox -u https://bgm.tv

# First-time HTTPS setup
bangumi-proxy --trust-ca
```

### Manual Browser Configuration

If you do not use `-b`, configure your browser manually:

```text
HTTP proxy:  127.0.0.1
HTTPS proxy: 127.0.0.1
Port:        8080
```

### Custom DNS

`--dns` accepts DoH URLs or plain DNS IPs. Separate multiple servers with commas:

```bash
bangumi-proxy --dns https://doh.pub/dns-query,1.1.1.1,8.8.8.8
```

### Custom Hosts

The hosts file uses the standard format:

```text
104.16.123.1 bgm.tv chii.in
104.16.123.2 lain.bgm.tv next.bgm.tv
```

Start the proxy with:

```bash
bangumi-proxy --hosts ./hosts
```

## Project Layout

```text
src/main.rs      Entry point, argument parsing, listener setup, browser launch
src/cli.rs       CLI flags and defaults
src/proxy.rs     HTTP/HTTPS proxy handling, CONNECT, MITM, tunnels, relay loops
src/backend.rs   Backend selection: ECH first, direct TLS fallback
src/browser.rs   Browser discovery and launch arguments
src/ca.rs        Local MITM CA generation, loading, and trust installation
src/dns.rs       DoH, plain DNS, system resolution, and A record parsing
src/ech.rs       ECH config caching, GREASE, and ECH TLS connections
src/hosts.rs     Custom hosts file parsing
src/targets.rs   Bangumi target hosts and Cloudflare IP range matching
ech_helper.c     OpenSSL ECH GREASE helper
build.rs         Detects OpenSSL ECH headers and compiles the C helper
```

## Notes

- The proxy is intended for local use only and listens on `127.0.0.1` by default.
- Target HTTPS sites require the local CA to be trusted, otherwise browsers will
  show certificate warnings.
- `ca-key.pem` is the local CA private key. Do not upload, share, or commit it.
- If the OpenSSL build does not include ECH support, the program can still build,
  but ECH connections will not be available.

## License

MIT
