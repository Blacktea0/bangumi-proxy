fn main() {
    // Register custom cfg names to suppress unexpected_cfgs warnings
    println!("cargo::rustc-check-cfg=cfg(has_ech)");
    println!("cargo::rustc-check-cfg=cfg(no_ech)");

    if cfg!(target_os = "windows") {
        // Windows: use scoop's static OpenSSL 4.0
        let openssl_dir = format!(
            "{}\\scoop\\apps\\openssl\\current",
            std::env::var("USERPROFILE").unwrap_or_default()
        );
        let lib_dir = format!("{openssl_dir}\\lib");
        let include_dir = format!("{openssl_dir}\\include");

        cc::Build::new()
            .file("ech_helper.c")
            .include(&include_dir)
            .compile("ech_helper");

        println!("cargo:rustc-env=OPENSSL_STATIC=1");
        println!("cargo:rustc-link-search=native={lib_dir}");
        println!("cargo:rustc-link-lib=static=libssl_static");
        println!("cargo:rustc-link-lib=static=libcrypto_static");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ntdll");
    } else {
        // Linux/macOS: support OPENSSL_DIR for custom OpenSSL (e.g. /opt/openssl-4.0)
        let openssl_dir = std::env::var("OPENSSL_DIR").ok();
        let openssl_include = std::env::var("OPENSSL_INCLUDE_DIR").ok()
            .or_else(|| openssl_dir.as_ref().map(|d| format!("{d}/include")))
            .or_else(|| {
                pkg_config::Config::new()
                    .atleast_version("3.0")
                    .probe("openssl")
                    .ok()
                    .and_then(|lib| lib.include_paths.into_iter().next().map(|p| p.display().to_string()))
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

        // Try to compile ECH helper — check ech.h for ECH APIs
        let ech_available = std::path::Path::new(&format!("{openssl_include}/openssl/ech.h")).exists();

        if ech_available {
            cc::Build::new()
                .file("ech_helper.c")
                .include(&openssl_include)
                .compile("ech_helper");
            println!("cargo:rustc-cfg=has_ech");
            println!("[build] ECH helper compiled (OpenSSL with ECH support)");
        } else {
            println!("cargo:rustc-cfg=no_ech");
            println!("[build] WARNING: ECH APIs not found — ECH features disabled");
            println!("[build] Set OPENSSL_DIR=/opt/openssl-4.0 for ECH support");
        }
    }
}
