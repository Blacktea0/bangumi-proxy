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

use ca::MitmCa;
use cli::Args;
use ech::EchCache;

fn main() -> io::Result<()> {
    let args = Args::parse();
    let addr = format!("127.0.0.1:{}", args.port);
    let ca = Arc::new(MitmCa::load_or_generate());
    let hosts = args
        .hosts
        .as_deref()
        .map(hosts::parse_hosts)
        .unwrap_or_default();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  bangumi-proxy — HTTP/HTTPS + ECH 绕过 GFW                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  代理: http://{addr:<44}║");
    println!("║  站点: chii.in / lain.bgm.tv / bgm.tv / next.bgm.tv       ║");
    println!("║  DNS:  {:<52} ║", args.dns);
    println!(
        "║  hosts:{:<52} ║",
        args.hosts.as_deref().unwrap_or("(none)")
    );
    println!("║  MITM: 自签 CA，支持 HTTPS                                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let cache = Arc::new(EchCache::new(args.dns.clone(), hosts));
    let listener = TcpListener::bind(&addr)?;
    println!("[proxy] Listening on {addr}\n");

    if args.browser {
        let chrome = args
            .chrome
            .clone()
            .or_else(browser::find_chrome)
            .unwrap_or_else(|| {
                eprintln!("[browser] Chrome not found");
                std::process::exit(1);
            });
        browser::launch_browser(&chrome, &addr, &args.url);
    } else {
        println!("Tip: use -b to auto-launch Chrome\n");
    }

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let (cache, ca) = (Arc::clone(&cache), Arc::clone(&ca));
            thread::spawn(move || proxy::handle_client(client, cache, ca));
        }
    }

    Ok(())
}
