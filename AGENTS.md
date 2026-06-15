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
  -p, --port <PORT>      监听端口 [default: 8080]
  -b, --browser          启动浏览器并自动配置代理
  -u, --url <URL>        浏览器启动后打开的 URL [default: http://chii.in]
      --chrome <CHROME>  Chrome 可执行文件路径（留空自动检测）
      --dns <DNS>        DoH URL 或纯 DNS IP [default: https://doh.pub/dns-query]
      --hosts <HOSTS>    自定义 hosts 文件路径（标准格式：IP domain）
```

### Examples

```bash
# Default: proxy on :8080, no browser
cargo run

# Launch Chrome with proxy, open bgm.tv
cargo run -- --browser --url http://bgm.tv

# Custom port
cargo run -- --port 9090

# Use custom hosts file (CF IPs → ECH, others → direct)
cargo run -- --hosts ./my_hosts.txt

# All options
cargo run -- -b -p 9090 -u http://lain.bgm.tv --hosts ./hosts
```

## Development

```powershell
# Build (requires OpenSSL 4.0 via scoop)
$env:OPENSSL_DIR = "$env:USERPROFILE\scoop\apps\openssl\current"
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib"
$env:OPENSSL_INCLUDE_DIR = "$env:OPENSSL_DIR\include"
cargo build

# Format
cargo fmt

# Check
cargo check

# Test
curl -x http://127.0.0.1:8080 http://chii.in/
```
