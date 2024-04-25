use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use lassecoin::client::ClientActor;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    addr: SocketAddr,
    #[arg(short, long)]
    path_to_root_accounts: String, 
    #[arg(short, long)]
    path_to_wallets: String,                                
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // read the root accounts files in the path_to_root_accounts

    let dir = std::fs::read_dir(&args.path_to_root_accounts).unwrap();
    let mut root_accounts = Vec::new();
    for entry in dir {
        let entry = entry.unwrap();
        let path = entry.path();
        let pem = std::fs::read_to_string(path).unwrap();
        let public_key = RsaPublicKey::from_public_key_pem(&pem).unwrap();
        root_accounts.push(public_key);
    } 

    ClientActor::run_root(args.addr, root_accounts, args.path_to_wallets).await;        

    loop {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
}