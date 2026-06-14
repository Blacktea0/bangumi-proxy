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
  -p, --port <PORT>      监听端口 [default: 8080]
  -b, --browser          启动浏览器并自动配置代理
  -u, --url <URL>        浏览器启动后打开的 URL [default: http://chii.in]
      --chrome <CHROME>  Chrome 可执行文件路径（留空自动检测）
```

### Examples

```bash
# Default: proxy on :8080, no browser
cargo run

# Launch Chrome with proxy, open bgm.tv
cargo run -- --browser --url http://bgm.tv

# Custom port
cargo run -- --port 9090

# All options
cargo run -- -b -p 9090 -u http://lain.bgm.tv
```

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
