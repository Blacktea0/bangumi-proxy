pub fn find_chrome() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        for candidate in &[
            "C:/Program Files/Google/Chrome/Application/chrome.exe",
            "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
            "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
        ] {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate.to_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for candidate in &[
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/microsoft-edge",
            "/usr/bin/microsoft-edge-stable",
            "/snap/bin/chromium",
        ] {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate.to_string());
            }
        }
    }

    which::which("google-chrome")
        .ok()
        .or_else(|| which::which("chromium").ok())
        .or_else(|| which::which("chromium-browser").ok())
        .or_else(|| which::which("microsoft-edge").ok())
        .or_else(|| which::which("msedge").ok())
        .map(|path| path.display().to_string())
}

pub fn launch_browser(chrome: &str, proxy: &str, url: &str) {
    let profile = format!("{}/bangumi-proxy", std::env::temp_dir().display());
    println!("[browser] {chrome} proxy=http://{proxy} url={url}");
    println!("[browser] profile={profile}\n");
    let _ = std::process::Command::new(chrome)
        .args([
            format!("--proxy-server=http://{proxy}"),
            "--remote-debugging-port=9222".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            format!("--user-data-dir={profile}"),
            "--ignore-certificate-errors".into(),
            url.into(),
        ])
        .spawn();
}
