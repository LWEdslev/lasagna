use std::{net::SocketAddr, str::FromStr, time::Duration};

use clap::Parser;
use lasagna::{client::ClientActor, ADDR, SEED_ADDR, WALLETS};

#[tokio::main]
async fn main() {
    let _ = *ADDR;
    let _ = *SEED_ADDR;
    let _ = *WALLETS;

    ClientActor::run(*SEED_ADDR, *ADDR).await;

    loop {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
}
