fn main() {
    if cfg!(target_os = "windows") {
        // Windows: check OPENSSL_DIR env first, fall back to scoop
        let openssl_dir = std::env::var("OPENSSL_DIR").ok().unwrap_or_else(|| {
            format!(
                "{}\\scoop\\apps\\openssl\\current",
                std::env::var("USERPROFILE").unwrap_or_default()
            )
        });
        let include_dir = std::env::var("OPENSSL_INCLUDE_DIR")
            .ok()
            .unwrap_or_else(|| format!("{openssl_dir}\\include"));
        let _lib_dir = std::env::var("OPENSSL_LIB_DIR")
            .ok()
            .unwrap_or_else(|| format!("{openssl_dir}\\lib"));

        let ech_header = format!("{include_dir}\\openssl\\ech.h");
        if !std::path::Path::new(&ech_header).exists() {
            panic!(
                "OpenSSL ECH header not found at {ech_header}; install OpenSSL 4.0 with ECH support and set OPENSSL_DIR/OPENSSL_INCLUDE_DIR"
            );
        }

        cc::Build::new()
            .static_crt(true)
            .file("ech_helper.c")
            .include(&include_dir)
            .compile("ech_helper");

        // Let openssl-sys handle OpenSSL linking via OPENSSL_DIR env
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ntdll");
    } else {
        // Linux/macOS: support OPENSSL_DIR for custom OpenSSL (e.g. /opt/openssl-4.0)
        let openssl_dir = std::env::var("OPENSSL_DIR").ok();
        let openssl_include = std::env::var("OPENSSL_INCLUDE_DIR")
            .ok()
            .or_else(|| openssl_dir.as_ref().map(|d| format!("{d}/include")))
            .or_else(|| {
                pkg_config::Config::new()
                    .atleast_version("3.0")
                    .probe("openssl")
                    .ok()
                    .and_then(|lib| {
                        lib.include_paths
                            .into_iter()
                            .next()
                            .map(|p| p.display().to_string())
                    })
            })
            .unwrap_or_else(|| "/usr/include".to_string());

        // Tell openssl-sys where to find custom OpenSSL
        if let Some(ref dir) = openssl_dir {
            let lib_dir = if std::path::Path::new(&format!("{dir}/lib64")).exists() {
                format!("{dir}/lib64")
            } else {
                format!("{dir}/lib")
            };
            println!("cargo:rustc-link-search=native={lib_dir}");
            // Also set env for openssl-sys crate
            println!("cargo:rustc-env=OPENSSL_DIR={dir}");
            println!("cargo:rustc-env=OPENSSL_LIB_DIR={lib_dir}");
            println!("cargo:rustc-env=OPENSSL_INCLUDE_DIR={openssl_include}");
        }

        let ech_header = format!("{openssl_include}/openssl/ech.h");
        if !std::path::Path::new(&ech_header).exists() {
            panic!(
                "OpenSSL ECH header not found at {ech_header}; install OpenSSL 4.0 with ECH support and set OPENSSL_DIR/OPENSSL_INCLUDE_DIR"
            );
        }

        cc::Build::new()
            .file("ech_helper.c")
            .include(&openssl_include)
            .compile("ech_helper");
        println!("[build] ECH helper compiled (OpenSSL with ECH support)");
    }
}
