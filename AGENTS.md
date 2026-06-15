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

- `src/main.rs` — HTTP proxy server with ECH (Encrypted Client Hello) support
- `ech_helper.c` — C helper for GREASE ECH (works around openssl-sys 32-bit `SSL_CTX_set_options` on Windows)
- `build.rs` — Compiles the C helper via the `cc` crate

## CLI Usage

```
bangumi-proxy [OPTIONS]

Options:
  -p, --port <PORT>        监听端口 [default: 8080]
  -b, --browser            启动浏览器并自动配置代理（自动检测，优先级：chrome > chromium > edge > firefox）
  -u, --url <URL>          浏览器启动后打开的 URL [default: http://chii.in]
      --chrome [PATH]      使用 Chrome（可选指定路径）
      --chromium [PATH]    使用 Chromium（可选指定路径）
      --edge [PATH]        使用 Edge（可选指定路径）
      --firefox [PATH]     使用 Firefox（可选指定路径）
      --dns <DNS>          DoH URL 或纯 DNS IP [default: https://doh.pub/dns-query]
      --hosts <HOSTS>      自定义 hosts 文件路径（标准格式：IP domain）
      --trust-ca           安装 CA 证书到系统信任根证书（首次使用或证书过期时运行）
```

### Examples

```bash
# Default: proxy on :8080, no browser
cargo run

# Auto-detect and launch browser with proxy
cargo run -- -b --url http://bgm.tv

# Use specific browser (auto-detect path)
cargo run -- --chrome
cargo run -- --edge --url http://bgm.tv
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
cargo run -- -b -p 9090 -u http://lain.bgm.tv --hosts ./hosts

## Development

```bash
# Build (requires OpenSSL 4.0 via scoop)
set OPENSSL_DIR=%USERPROFILE%\scoop\apps\openssl\current
set OPENSSL_LIB_DIR=%OPENSSL_DIR%\lib
set OPENSSL_INCLUDE_DIR=%OPENSSL_DIR%\include
cargo build

# Test
curl -x http://127.0.0.1:8080 http://chii.in/
```
