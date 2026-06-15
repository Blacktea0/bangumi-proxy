# AGENTS.md

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <description>

[optional body]
[optional footer(s)]
```

### Types

| Type       | Description                           |
|------------|---------------------------------------|
| `feat`     | New feature                           |
| `fix`      | Bug fix                               |
| `docs`     | Documentation only                    |
| `style`    | Code style (formatting, no logic)     |
| `refactor` | Code restructure (no feature/fix)     |
| `perf`     | Performance improvement               |
| `test`     | Adding or updating tests              |
| `build`    | Build system or dependencies          |
| `ci`       | CI/CD configuration                   |
| `chore`    | Maintenance tasks                     |

### Examples

```
feat(proxy): add ECH proxy for chii.in and bgm.tv
fix(dns): handle DNSPod Answer array parsing correctly
build(deps): add parking_lot and cc dependencies
refactor(ech): extract GREASE ECH into C helper for Windows compat
```

### Rules

- Subject line: imperative mood, lowercase, no period, max 72 chars
- Body: wrap at 72 chars, explain what and why (not how)
- Footer: reference issues (`Closes #123`) or breaking changes (`BREAKING CHANGE: ...`)

## Architecture

- `src/main.rs` — entry point, argument parsing, listener setup, browser launch
- `src/cli.rs` — CLI flags and defaults
- `src/proxy.rs` — HTTP/HTTPS proxy request handling and CONNECT tunneling
- `src/backend.rs` — upstream connection selection
- `src/browser.rs` — Chrome discovery and launch with proxy settings
- `src/ca.rs` — local MITM CA loading and generation
- `src/dns.rs` — DNS and DoH resolution
- `src/ech.rs` — ECH (Encrypted Client Hello) state and TLS integration
- `src/hosts.rs` — custom hosts file parsing
- `src/targets.rs` — supported Bangumi target host rules
- `ech_helper.c` — C helper for GREASE ECH; this works around
  `openssl-sys` compatibility gaps on Windows
- `build.rs` — detects OpenSSL ECH headers and compiles `ech_helper.c`

## CLI Usage

```
bangumi-proxy [OPTIONS]

Options:
  -p, --port <PORT>        Listening port [default: 8080]
  -b, --browser            Launch browser with auto-configured proxy (auto-detect priority: chrome > chromium > edge > firefox)
  -u, --url <URL>          URL to open in browser [default: https://bgm.tv]
      --chrome [PATH]      Use Chrome (optional custom path)
      --chromium [PATH]    Use Chromium (optional custom path)
      --edge [PATH]        Use Edge (optional custom path)
      --firefox [PATH]     Use Firefox (optional custom path)
      --dns <DNS>          DoH URL or plain DNS IP [default: https://doh.pub/dns-query]
      --hosts <HOSTS>      Custom hosts file path (standard format: IP domain)
      --trust-ca           Install CA certificate to system trust store (run on first use or when certificate expires)
```

### Examples

```bash
# Default: proxy on :8080, no browser
cargo run

# Auto-detect and launch browser with proxy
cargo run -- -b --url https://bgm.tv

# Use specific browser (auto-detect path)
cargo run -- --chrome
cargo run -- --edge --url https://bgm.tv
cargo run -- --firefox

# Use specific browser with custom path
cargo run -- --chrome "C:/path/to/chrome.exe"
cargo run -- --firefox "/usr/bin/firefox"

# Custom port
cargo run -- --port 9090

# Use custom hosts file (CF IPs → ECH, others → direct)
cargo run -- --hosts ./my_hosts.txt

# Trust CA certificate (first-time setup, installs to OS trust store)
cargo run -- --trust-ca

# All options
cargo run -- -b -p 9090 -u https://lain.bgm.tv --hosts ./hosts

## Development

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Conan 2.x](https://conan.io/) (`pip install conan` or `pipx install conan`)
- C compiler (MSVC on Windows, gcc/clang on Linux/macOS)

### Build

```bash
# 1. Install OpenSSL 4.0 via Conan (first time only)
conan profile detect --force
# Linux/macOS:
conan install conan --build=missing -s build_type=Release
# Windows (needs static CRT to match Rust MSVC default):
conan install conan --build=missing -s build_type=Release -s compiler.runtime=static

# 2. Set OpenSSL environment variables
# Linux/macOS:
CONAN_PKG=$(find ~/.conan2/p -path "*/p/include/openssl/ech.h" 2>/dev/null | head -1 | sed 's|/include/openssl/ech.h||')
export OPENSSL_DIR=$CONAN_PKG
export OPENSSL_INCLUDE_DIR=$CONAN_PKG/include
export OPENSSL_LIB_DIR=$CONAN_PKG/lib
export OPENSSL_STATIC=1

# Windows (PowerShell):
$libFile = Get-ChildItem -Path "$env:USERPROFILE\.conan2\p" -Recurse -Filter "libssl.lib" -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "\\p\\lib\\" } | Select-Object -First 1
$CONAN_PKG = $libFile.Directory.Parent.FullName
$env:OPENSSL_DIR = $CONAN_PKG
$env:OPENSSL_INCLUDE_DIR = "$CONAN_PKG\include"
$env:OPENSSL_LIB_DIR = $libFile.DirectoryName
$env:OPENSSL_STATIC = "1"

# 3. Build
cargo build
cargo build --release

# 4. Test
curl -x http://127.0.0.1:8080 http://chii.in/
```
