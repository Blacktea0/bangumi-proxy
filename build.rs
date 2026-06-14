fn main() {
    let openssl_dir = format!("{}\\scoop\\apps\\openssl\\current",
        std::env::var("USERPROFILE").unwrap_or_default());

    cc::Build::new()
        .file("ech_helper.c")
        .include(format!("{openssl_dir}\\include"))
        .compile("ech_helper");
}
