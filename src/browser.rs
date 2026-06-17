#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BrowserKind {
    Chrome,
    Chromium,
    Edge,
    Firefox,
}

impl BrowserKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
        }
    }

    pub fn is_chromium(self) -> bool {
        matches!(self, Self::Chrome | Self::Chromium | Self::Edge)
    }
}

pub fn find_browser(kind: BrowserKind) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => &[
                "C:/Program Files/Google/Chrome/Application/chrome.exe",
                "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
            ],
            BrowserKind::Chromium => &[
                "C:/Program Files/Chromium/Application/chrome.exe",
                "C:/Program Files (x86)/Chromium/Application/chrome.exe",
            ],
            BrowserKind::Edge => &[
                "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
                "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
            ],
            BrowserKind::Firefox => &[
                "C:/Program Files/Mozilla Firefox/firefox.exe",
                "C:/Program Files (x86)/Mozilla Firefox/firefox.exe",
            ],
        };
        for c in candidates {
            if std::path::Path::new(c).exists() {
                return Some(c.to_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => &["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
            BrowserKind::Chromium => &[
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/snap/bin/chromium",
            ],
            BrowserKind::Edge => &["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"],
            BrowserKind::Firefox => &["/usr/bin/firefox", "/usr/bin/firefox-esr"],
        };
        for c in candidates {
            if std::path::Path::new(c).exists() {
                return Some(c.to_string());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let candidates: &[&str] = match kind {
            BrowserKind::Chrome => {
                &["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
            }
            BrowserKind::Chromium => &["/Applications/Chromium.app/Contents/MacOS/Chromium"],
            BrowserKind::Edge => {
                &["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
            }
            BrowserKind::Firefox => &["/Applications/Firefox.app/Contents/MacOS/firefox"],
        };
        for c in candidates {
            if std::path::Path::new(c).exists() {
                return Some(c.to_string());
            }
        }
    }

    let names: &[&str] = match kind {
        BrowserKind::Chrome => &["google-chrome", "chrome"],
        BrowserKind::Chromium => &["chromium", "chromium-browser"],
        BrowserKind::Edge => &["microsoft-edge", "msedge"],
        BrowserKind::Firefox => &["firefox", "firefox-esr"],
    };
    for n in names {
        if let Some(p) = which::which(n).ok() {
            return Some(p.display().to_string());
        }
    }
    None
}

/// Auto-detect browser with priority: chrome > chromium > edge > firefox
pub fn auto_detect_browser() -> Option<(BrowserKind, String)> {
    for kind in [
        BrowserKind::Chrome,
        BrowserKind::Chromium,
        BrowserKind::Edge,
        BrowserKind::Firefox,
    ] {
        if let Some(path) = find_browser(kind) {
            return Some((kind, path));
        }
    }
    None
}

/// Resolve profile directory for the browser. On Linux, snap packages cannot
/// access `/tmp`, so we use the snap's home directory instead.
fn browser_profile_dir(kind: BrowserKind, exe: &str) -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = snap_profile_dir(kind, exe) {
            return std::path::PathBuf::from(dir);
        }
    }
    let _ = (kind, exe);
    std::env::temp_dir().join("bangumi-proxy")
}

#[cfg(target_os = "linux")]
fn snap_profile_dir(kind: BrowserKind, exe: &str) -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    // Detect snap browsers: /snap/bin/chromium, /snap/firefox/.../firefox,
    // or the distro wrapper scripts that delegate to snap.
    let snap_name = if exe.starts_with("/snap/") {
        // /snap/bin/chromium → chromium; /snap/firefox/8107/.../firefox → firefox
        if exe.contains("firefox") {
            "firefox"
        } else {
            "chromium"
        }
    } else if kind.is_chromium()
        && (exe == "/usr/bin/chromium-browser" || exe == "/usr/bin/chromium")
        && std::path::Path::new("/snap/chromium").exists()
    {
        "chromium"
    } else if kind == BrowserKind::Firefox
        && exe == "/usr/bin/firefox"
        && std::path::Path::new("/snap/firefox").exists()
    {
        "firefox"
    } else {
        return None;
    };
    Some(format!("{home}/snap/{snap_name}/common/bangumi-proxy"))
}
pub fn launch_browser(kind: BrowserKind, exe: &str, proxy: &str, url: &str, ca_trusted: bool) {
    let profile = browser_profile_dir(kind, exe);
    let profile_s = profile.display().to_string();
    println!("[browser] {} proxy=http://{proxy} url={url}", kind.name());
    println!("[browser] exe={exe}");
    println!(
        "[browser] CA trust={}",
        if ca_trusted { "trusted" } else { "untrusted" }
    );
    println!("[browser] profile={profile_s}\n");

    if kind.is_chromium() {
        let mut args = vec![
            format!("--proxy-server=http://{proxy}"),
            "--remote-debugging-port=9222".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            format!("--user-data-dir={profile_s}"),
        ];
        if !ca_trusted {
            args.push("--ignore-certificate-errors".into());
        }
        #[cfg(target_os = "linux")]
        {
            extern "C" {
                fn geteuid() -> u32;
            }
            // Chromium refuses to run as root without --no-sandbox.
            if unsafe { geteuid() } == 0 {
                args.push("--no-sandbox".into());
            }
        }
        args.push(url.into());
        match std::process::Command::new(exe).args(&args).spawn() {
            Ok(_) => {}
            Err(e) => eprintln!("[browser] failed to launch {}: {e}", kind.name()),
        }
    } else {
        // Firefox: create profile with proxy prefs in user.js (never
        // overwritten by Firefox, unlike prefs.js).
        let (host, port) = proxy.rsplit_once(':').unwrap_or(("127.0.0.1", "8080"));
        let _ = std::fs::create_dir_all(&profile);
        let _ = std::fs::write(profile.join("user.js"), {
            let mut prefs = format!(
                "user_pref(\"network.proxy.type\", 1);\n\
                 user_pref(\"network.proxy.http\", \"{host}\");\n\
                 user_pref(\"network.proxy.http_port\", {port});\n\
                 user_pref(\"network.proxy.ssl\", \"{host}\");\n\
                 user_pref(\"network.proxy.ssl_port\", {port});\n\
                 user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
                 user_pref(\"security.enterprise_roots.enabled\", true);\n",
            );
            if !ca_trusted {
                prefs.push_str(
                    "user_pref(\"security.OCSP.enabled\", 0);\n\
                         user_pref(\"security.cert_pinning.enforcement_level\", 0);\n",
                );
            }
            prefs
        });
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["--no-remote", "--profile", profile_s.as_str(), url]);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000010); // CREATE_NEW_CONSOLE
        }
        match cmd.spawn() {
            Ok(_) => {}
            Err(e) => eprintln!("[browser] failed to launch firefox: {e}"),
        }
    }
}

/// Detect if the program was launched by double-clicking (GUI) vs from a terminal.
#[cfg(windows)]
pub fn is_gui_launch() -> bool {
    use std::mem::MaybeUninit;
    extern "system" {
        fn GetConsoleProcessList(lpdwProcessList: *mut u32, dwProcessCount: u32) -> u32;
    }
    let mut pids = [MaybeUninit::<u32>::uninit(); 16];
    let count = unsafe { GetConsoleProcessList(pids[0].as_mut_ptr(), 16) };
    count <= 1
}

#[cfg(not(windows))]
pub fn is_gui_launch() -> bool {
    false
}
