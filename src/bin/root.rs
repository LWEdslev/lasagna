use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use lasagna::{client::ClientActor, MainArgs, RootArgs, ARGS};
use rand::thread_rng;
use rsa::{pkcs8::DecodePublicKey, sha2::{Digest, Sha256}, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};

#[tokio::main]
async fn main() {

    

    let args: RootArgs = match ARGS.clone() {
        MainArgs::Root(a) => a,
        MainArgs::Regular(_) => panic!("Use root arguments"),
    };

    // read the root accounts files in the path_to_root_accounts
    let dir = std::fs::read_dir(&args.root).unwrap();
    let mut root_accounts = Vec::new();
    for entry in dir {
        let entry = entry.unwrap();
        let path = entry.path();
        let pem = std::fs::read_to_string(path).unwrap();
        let public_key = RsaPublicKey::from_public_key_pem(&pem).unwrap();
        root_accounts.push(public_key);
    }

    ClientActor::run_root(args.addr, root_accounts).await;

    loop {
        tokio::time::sleep(Duration::from_secs(100)).await;
    }
}
