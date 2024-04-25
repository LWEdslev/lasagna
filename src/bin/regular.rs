use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use lassecoin::client::ClientActor;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    addr: SocketAddr,
    #[arg(short, long)]
    seed_addr: SocketAddr,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    ClientActor::run(args.seed_addr, args.addr).await;        

    loop {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
}