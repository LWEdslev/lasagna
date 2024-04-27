use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use lasagna::{client::ClientActor, MainArgs, RegArgs, ARGS};

#[tokio::main]
async fn main() {
    let args: RegArgs = match ARGS.clone() {
        MainArgs::Root(_) => panic!("must provide regular args"),
        MainArgs::Regular(a) => a,
    };

    ClientActor::run(args.seed_addr, args.addr).await;

    loop {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
}
