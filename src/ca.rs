use std::io::Write;
use std::path::Path;

pub struct MitmCa {
    ca_key: rcgen::KeyPair,
    ca_cert: rcgen::Certificate,
}

/// Common CA certificate params with proper Subject DN and KeyUsage.
fn ca_params() -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "bangumi-proxy CA");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

impl MitmCa {
    pub fn load_or_generate() -> Self {
        let cp = std::env::current_dir().unwrap_or_default().join("ca.pem");
        let kp = std::env::current_dir()
            .unwrap_or_default()
            .join("ca-key.pem");
        if cp.exists() && kp.exists() {
            println!("[CA] Loaded from {}", cp.display());
            let key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&kp).unwrap()).unwrap();
            let params = ca_params();
            return Self {
                ca_cert: params.self_signed(&key).unwrap(),
                ca_key: key,
            };
        }

        println!("[CA] Generating...");
        let key = rcgen::KeyPair::generate().unwrap();
        let params = ca_params();
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(&cp, cert.pem()).unwrap();
        std::fs::write(&kp, key.serialize_pem()).unwrap();
        println!("[CA] Saved to {}", cp.display());

        Self {
            ca_cert: cert,
            ca_key: key,
        }
    }

    pub fn server_config(&self, host: &str) -> rustls::ServerConfig {
        let host_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let host_cert = params
            .signed_by(&host_key, &self.ca_cert, &self.ca_key)
            .unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            host_cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(host_key.serialize_der());

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::from(key))
            .unwrap()
    }
}

fn decode_pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;

    for line in pem.lines().map(str::trim) {
        if line == "-----BEGIN CERTIFICATE-----" {
            current.clear();
            in_cert = true;
        } else if line == "-----END CERTIFICATE-----" {
            if in_cert {
                use base64::Engine;
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&current) {
                    certs.push(der);
                }
            }
            current.clear();
            in_cert = false;
        } else if in_cert {
            current.push_str(line);
        }
    }

    certs
}

fn read_pem_certificate_der(path: &Path) -> std::io::Result<Vec<u8>> {
    let pem = std::fs::read_to_string(path)?;
    decode_pem_certificates(&pem)
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no certificate found"))
}

#[cfg(windows)]
fn powershell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(windows)]
fn windows_root_store_has_certificate(ca_der: &Path) -> bool {
    let Some(path) = ca_der.to_str() else {
        return false;
    };
    let script = format!(
        "$path = (Resolve-Path -LiteralPath {}).Path; \
         $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path); \
         $found = Get-ChildItem -Path Cert:\\LocalMachine\\Root,Cert:\\CurrentUser\\Root -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.Thumbprint -eq $cert.Thumbprint }} | Select-Object -First 1; \
         if ($null -ne $found) {{ exit 0 }} else {{ exit 1 }}",
        powershell_single_quoted(path)
    );

    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Trust CA certificate. Returns true if already trusted (no action needed).
/// prompt=true: interactive mode (--trust-ca), prompts to install if untrusted;
/// prompt=false: silent check, only prints warning if untrusted.
pub fn trust_ca(prompt: bool) -> bool {
    let dir = std::env::current_dir().unwrap_or_default();
    let ca_pem = dir.join("ca.pem");
    if !ca_pem.exists() {
        eprintln!("[trust] ca.pem not found — run bangumi-proxy first to generate CA");
        return false;
    }
    let ca_der = dir.join("ca.cer");
    let ca_der_bytes = match read_pem_certificate_der(&ca_pem) {
        Ok(der) => der,
        Err(err) => {
            eprintln!("[trust] failed to read CA certificate: {err}");
            return false;
        }
    };

    // ---- Windows: certutil -addstore Root ----
    #[cfg(windows)]
    {
        std::fs::write(&ca_der, &ca_der_bytes).unwrap();
        println!("[trust] DER: {}", ca_der.display());
        if windows_root_store_has_certificate(&ca_der) {
            println!("[trust] ✓ Current CA already trusted (Windows Root store)");
            return true;
        }
        if !prompt {
            println!("[trust] Not yet trusted. Run: bangumi-proxy --trust-ca");
            return false;
        }
        println!("[trust] Not yet trusted. Install to Windows Root store:");
        println!("  certutil -addstore Root \"{}\"", ca_der.display());
        print!("  Run automatically now? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        if !buf.trim().eq_ignore_ascii_case("n") {
            match std::process::Command::new("certutil")
                .args(["-addstore", "Root", ca_der.to_str().unwrap()])
                .status()
            {
                Ok(s) if s.success() => {
                    println!("[trust] ✓ Installed");
                    return true;
                }
                _ => println!("[trust] Failed — run the command above as Administrator"),
            }
        }
        return false;
    }

    // ---- Linux: ca-certificates / ca-trust ----
    #[cfg(target_os = "linux")]
    {
        let target_dir = if std::path::Path::new("/etc/pki/ca-trust/source/anchors").exists() {
            std::path::PathBuf::from("/etc/pki/ca-trust/source/anchors")
        } else {
            std::path::PathBuf::from("/usr/local/share/ca-certificates")
        };
        let target = target_dir.join("bangumi-proxy-ca.crt");
        if target.exists()
            && read_pem_certificate_der(&target)
                .map(|installed_der| installed_der == ca_der_bytes)
                .unwrap_or(false)
        {
            println!(
                "[trust] ✓ Current CA already installed: {}",
                target.display()
            );
            return true;
        }
        if !prompt {
            println!("[trust] Not yet trusted. Run: bangumi-proxy --trust-ca");
            return false;
        }
        println!("[trust] Copy ca.pem to system trust store:");
        println!(
            "  sudo cp \"{}\" \"{}\"",
            ca_pem.display(),
            target.display()
        );
        if target_dir.ends_with("anchors") {
            println!("  sudo update-ca-trust");
        } else {
            println!("  sudo update-ca-certificates");
        }
        print!("  Run automatically now? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        if !buf.trim().eq_ignore_ascii_case("n") {
            if let Ok(s) = std::process::Command::new("sudo")
                .args(["cp", ca_pem.to_str().unwrap(), target.to_str().unwrap()])
                .status()
            {
                if s.success() {
                    let update = if target_dir.ends_with("anchors") {
                        "update-ca-trust"
                    } else {
                        "update-ca-certificates"
                    };
                    let _ = std::process::Command::new("sudo").arg(update).status();
                    println!("[trust] ✓ Installed");
                    return true;
                }
            }
            println!("[trust] Failed — run the commands above manually");
        }
        return false;
    }

    // ---- macOS: security add-trusted-cert ----
    #[cfg(target_os = "macos")]
    {
        let check = std::process::Command::new("security")
            .args([
                "find-certificate",
                "-c",
                "bangumi-proxy CA",
                "/Library/Keychains/System.keychain",
            ])
            .output();
        let trusted = check
            .map(|o| {
                o.status.success()
                    && decode_pem_certificates(&String::from_utf8_lossy(&o.stdout))
                        .into_iter()
                        .any(|installed_der| installed_der == ca_der_bytes)
            })
            .unwrap_or(false);
        if trusted {
            println!("[trust] ✓ Current CA already trusted (macOS System keychain)");
            return true;
        }
        if !prompt {
            println!("[trust] Not yet trusted. Run: bangumi-proxy --trust-ca");
            return false;
        }
        println!("[trust] Add to macOS System keychain:");
        println!(
            "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"{}\"",
            ca_pem.display()
        );
        print!("  Run automatically now? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        if !buf.trim().eq_ignore_ascii_case("n") {
            match std::process::Command::new("sudo")
                .args([
                    "security",
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    ca_pem.to_str().unwrap(),
                ])
                .status()
            {
                Ok(s) if s.success() => {
                    println!("[trust] ✓ Installed");
                    return true;
                }
                _ => println!("[trust] Failed — run the command above manually"),
            }
        }
        return false;
    }
}
