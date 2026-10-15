//! A stand-in phone for the daemon's end-to-end test (M62 stage 4).
//!
//! Dials a running `fermix-iroh` directly at one UDP address, with no relay,
//! offering `fermix/mobile/1`, opens one bidirectional stream and copies stdin
//! to the stream and the stream to stdout. When stdin ends it finishes its
//! sending half; when the stream's receiving half ends it drops its sending
//! half (so the stream's credit comes back, `DEVIATIONS.md` B7) and exits 0.
//! Any failure exits 1 with one line on stderr.
//!
//! An example, so it is never built into the released binary:
//! `cargo build --release --example test_peer`, then
//! `test_peer <endpoint id> <ip:port>`.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use iroh::endpoint::{PortmapperConfig, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"fermix/mobile/1";
const CHUNK_BYTES: usize = 65_536;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("test_peer: {message}");
            1
        }
    };

    // Exit here: returning would drop the runtime, which waits for the
    // blocking stdin read the abandoned upstream copy is still in.
    std::process::exit(code);
}

async fn run() -> Result<(), String> {
    let (id, addr) = arguments()?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("bind address: {e}"))?
        .bind()
        .await
        .map_err(|e| format!("bind: {e}"))?;

    let connection = endpoint
        .connect(EndpointAddr::new(id).with_ip_addr(addr), ALPN)
        .await
        .map_err(|e| format!("dial: {e}"))?;

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("open stream: {e}"))?;

    // The daemon's answers decide when the session is over; stdin may stay
    // open after it, so the upstream copy is abandoned, not awaited.
    let upstream = tokio::spawn(upstream(send));
    let result = downstream(recv).await;
    upstream.abort();
    endpoint.close().await;
    result
}

fn arguments() -> Result<(EndpointId, SocketAddr), String> {
    let mut args = std::env::args().skip(1);

    match (args.next(), args.next(), args.next()) {
        (Some(id), Some(addr), None) => {
            let id = EndpointId::from_str(&id).map_err(|e| format!("endpoint id: {e}"))?;
            let addr = addr.parse().map_err(|e| format!("address: {e}"))?;
            Ok((id, addr))
        }
        _ => Err("usage: test_peer <endpoint id> <ip:port>".into()),
    }
}

async fn upstream(mut send: SendStream) -> Result<(), String> {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; CHUNK_BYTES];

    loop {
        let read = stdin.read(&mut buf).await.map_err(|e| e.to_string())?;

        if read == 0 {
            return send.finish().map_err(|e| e.to_string());
        }

        send.write_all(&buf[..read])
            .await
            .map_err(|e| e.to_string())?;
    }
}

async fn downstream(mut recv: RecvStream) -> Result<(), String> {
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; CHUNK_BYTES];

    loop {
        match recv
            .read(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?
        {
            Some(read) => {
                stdout
                    .write_all(&buf[..read])
                    .await
                    .map_err(|e| e.to_string())?;
                stdout.flush().await.map_err(|e| e.to_string())?;
            }
            None => return Ok(()),
        }
    }
}
