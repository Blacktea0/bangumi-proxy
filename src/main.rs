mod backend;
mod browser;
mod ca;
mod cli;
mod dns;
mod ech;
mod hosts;
mod proxy;
mod targets;

use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use clap::Parser;

use browser::BrowserKind;
use ca::MitmCa;
use cli::Args;
use ech::EchCache;

fn main() -> io::Result<()> {
    let args = Args::parse();
    let addr = format!("127.0.0.1:{}", args.port);
    let ca = Arc::new(MitmCa::load_or_generate());

    let already_trusted = ca::trust_ca(args.trust_ca);
    if args.trust_ca {
        if already_trusted {
            println!("[trust] Nothing to do — CA already trusted.");
        }
        return Ok(());
    }

    let hosts = args
        .hosts
        .as_deref()
        .map(hosts::parse_hosts)
        .unwrap_or_default();

    println!("bangumi-proxy — HTTP/HTTPS + ECH proxy");
    println!("  Proxy:  http://{addr}");
    println!("  Sites:  chii.in / lain.bgm.tv / bgm.tv / next.bgm.tv");
    println!("  DNS:    {}", args.dns.join(", "));
    println!("  Hosts:  {}", args.hosts.as_deref().unwrap_or("(none)"));
    println!("  MITM:   self-signed CA, HTTPS enabled");
    println!("  Cert:   {}", std::env::current_dir().unwrap_or_default().join("ca.pem").display());

    let cache = Arc::new(EchCache::new(args.dns.clone(), hosts));
    let listener = TcpListener::bind(&addr)?;
    println!("[proxy] Listening on {addr}\n");

    // Resolve browser launch: specific flag > -b auto-detect > gui fallback
    let browser_req: Option<(BrowserKind, Option<String>)> =
        args.chrome.clone().map(|p| (BrowserKind::Chrome, p.filter(|s| !s.is_empty())))
        .or_else(|| args.chromium.clone().map(|p| (BrowserKind::Chromium, p.filter(|s| !s.is_empty()))))
        .or_else(|| args.edge.clone().map(|p| (BrowserKind::Edge, p.filter(|s| !s.is_empty()))))
        .or_else(|| args.firefox.clone().map(|p| (BrowserKind::Firefox, p.filter(|s| !s.is_empty()))));

    let gui_launch = browser::is_gui_launch();
    if gui_launch {
        if let Some((kind, exe)) = browser::auto_detect_browser() {
            browser::launch_browser(kind, &exe, &addr, "https://bgm.tv");
        } else {
            eprintln!("[browser] No supported browser found");
        }
    } else if let Some((kind, explicit_path)) = browser_req {
        let exe = explicit_path.or_else(|| browser::find_browser(kind)).unwrap_or_else(|| {
            eprintln!("[browser] {} not found", kind.name());
            std::process::exit(1);
        });
        browser::launch_browser(kind, &exe, &addr, &args.url);
    } else if args.browser {
        if let Some((kind, exe)) = browser::auto_detect_browser() {
            browser::launch_browser(kind, &exe, &addr, &args.url);
        } else {
            eprintln!("[browser] No supported browser found");
            std::process::exit(1);
        }
    } else {
        println!("Tip: use -b to auto-launch browser, or --chrome/--edge/--firefox\n");
    }

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let (cache, ca) = (Arc::clone(&cache), Arc::clone(&ca));
            thread::spawn(move || proxy::handle_client(client, cache, ca));
        }
    }

    Ok(())
}
