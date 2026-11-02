//! Measures plain I2P streams through SAM: how long sessions take to start, how long a first
//! connection takes, the round trip, and throughput for one stream and for several at once.
//! Usage: samtest <sam port> <hops> <megabytes> <parallel streams>
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yosemite::{style::Stream, Session, SessionOptions};

fn options(port: u16, hops: usize, name: &str) -> SessionOptions {
    SessionOptions {
        samv3_tcp_port: port,
        nickname: name.to_string(),
        inbound_len: hops,
        outbound_len: hops,
        ..Default::default()
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).map_or(7656, |a| a.parse().unwrap());
    let hops: usize = args.get(2).map_or(3, |a| a.parse().unwrap());
    let mb: usize = args.get(3).map_or(4, |a| a.parse().unwrap());
    let parallel: usize = args.get(4).map_or(4, |a| a.parse().unwrap());
    let t0 = Instant::now();
    let log = move |msg: String| println!("{:7.1}s {msg}", t0.elapsed().as_secs_f64());

    let mut server = Session::<Stream>::new(options(port, hops, "anathemic-server")).await.expect("server session");
    let destination = server.destination().to_owned();
    log(format!("server session up ({} hops)", hops));
    tokio::spawn(async move {
        while let Ok(mut stream) = server.accept().await {
            tokio::spawn(async move {
                // Request: 1 byte 'p' (ping, echo 1 byte) or 'g' + u32 length
                let mut kind = [0u8; 1];
                while stream.read_exact(&mut kind).await.is_ok() {
                    if kind[0] == b'p' {
                        if stream.write_all(b"p").await.is_err() { return; }
                    } else {
                        let mut len = [0u8; 4];
                        stream.read_exact(&mut len).await.unwrap();
                        let len = u32::from_be_bytes(len) as usize;
                        let chunk = vec![7u8; 64 << 10];
                        let mut sent = 0;
                        while sent < len {
                            let n = chunk.len().min(len - sent);
                            if stream.write_all(&chunk[..n]).await.is_err() { return; }
                            sent += n;
                        }
                    }
                }
            });
        }
    });

    // One client: connect, round trips, one big download
    let started = Instant::now();
    let mut client = Session::<Stream>::new(options(port, hops, "anathemic-client")).await.expect("client session");
    log(format!("client session up after {:.1}s", started.elapsed().as_secs_f64()));
    let started = Instant::now();
    let mut stream = loop {
        match tokio::time::timeout(Duration::from_secs(120), client.connect(&destination)).await {
            Ok(Ok(stream)) => break stream,
            other => log(format!("connect failed ({:?}); retrying", other.map(|r| r.err()))),
        }
    };
    log(format!("RESULT first connect took {:.1}s", started.elapsed().as_secs_f64()));
    let mut rtts = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        stream.write_all(b"p").await.unwrap();
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await.unwrap();
        rtts.push(started.elapsed().as_secs_f64());
    }
    log(format!("RESULT round trips: {}", rtts.iter().map(|r| format!("{r:.2}s")).collect::<Vec<_>>().join(" ")));
    let size = mb << 20;
    let started = Instant::now();
    stream.write_all(b"g").await.unwrap();
    stream.write_all(&(size as u32).to_be_bytes()).await.unwrap();
    let mut buf = vec![0u8; 64 << 10];
    let mut got = 0;
    let mut next_report = 1 << 20;
    while got < size {
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "stream closed");
        got += n;
        if got >= next_report {
            log(format!("  {} MB", got >> 20));
            next_report += 1 << 20;
        }
    }
    let secs = started.elapsed().as_secs_f64();
    log(format!("RESULT one stream: {mb} MB in {secs:.1}s = {:.0} KB/s", size as f64 / 1024.0 / secs));

    // Several streams at once, from one session (like pieces from one peer) 
    let started = Instant::now();
    let per = size / parallel;
    let mut tasks = Vec::new();
    for _ in 0..parallel {
        let mut stream = client.connect(&destination).await.expect("connect");
        tasks.push(tokio::spawn(async move {
            stream.write_all(b"g").await.unwrap();
            stream.write_all(&(per as u32).to_be_bytes()).await.unwrap();
            let mut buf = vec![0u8; 64 << 10];
            let mut got = 0;
            while got < per {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                got += n;
            }
        }));
    }
    for t in tasks { t.await.unwrap(); }
    let secs = started.elapsed().as_secs_f64();
    log(format!("RESULT {parallel} streams together: {mb} MB in {secs:.1}s = {:.0} KB/s", size as f64 / 1024.0 / secs));
}
