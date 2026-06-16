use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bangumi-proxy", version, about = "HTTP/HTTPS proxy + ECH")]
pub struct Args {
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
    #[arg(short, long)]
    pub browser: bool,
    #[arg(short, long, default_value = "https://bgm.tv")]
    pub url: String,
    /// Use Chrome (optional custom path)
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub chrome: Option<Option<String>>,
    /// Use Chromium (optional custom path)
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub chromium: Option<Option<String>>,
    /// Use Edge (optional custom path)
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub edge: Option<Option<String>>,
    /// Use Firefox (optional custom path)
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub firefox: Option<Option<String>>,
    /// DoH URL or plain DNS IP, comma-separated
    #[arg(
        long,
        default_value = "https://doh.pub/dns-query",
        value_delimiter = ','
    )]
    pub dns: Vec<String>,
    /// Custom hosts file path (standard format: IP domain)
    #[arg(long)]
    pub hosts: Option<String>,
    /// Install CA certificate to system trust store (run on first use or when certificate expires)
    #[arg(long)]
    pub trust_ca: bool,
}
