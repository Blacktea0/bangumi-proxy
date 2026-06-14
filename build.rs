fn main() {
    let openssl_dir = format!(
        "{}\\scoop\\apps\\openssl\\current",
        std::env::var("USERPROFILE").unwrap_or_default()
    );
    let lib_dir = format!("{openssl_dir}\\lib");
    let include_dir = format!("{openssl_dir}\\include");

    // Compile C helper against OpenSSL headers
    cc::Build::new()
        .file("ech_helper.c")
        .include(&include_dir)
        .compile("ech_helper");

    // Tell openssl-sys to link statically
    println!("cargo:rustc-env=OPENSSL_STATIC=1");
    println!("cargo:rustc-link-search=native={lib_dir}");

    // Static OpenSSL on Windows needs these system libs
    println!("cargo:rustc-link-lib=static=libssl_static");
    println!("cargo:rustc-link-lib=static=libcrypto_static");
    println!("cargo:rustc-link-lib=ws2_32");
    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=bcrypt");
    println!("cargo:rustc-link-lib=ntdll");
}
