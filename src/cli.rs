use std::{fs::ReadDir, time::Duration};

use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{
    pkcs1::EncodeRsaPublicKey, pkcs8::{der::zeroize::Zeroizing, DecodePublicKey}, RsaPrivateKey, RsaPublicKey
};
use tokio::{io::BufReader, sync::mpsc::Sender};
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncBufRead;

use crate::{transaction::Transaction, CLIMessage, ClientMessage, Error, Result, ARGS, WALLETS};

pub(crate) async fn read_line() -> String {
    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    reader.read_line(&mut line).await.unwrap();
    line.trim().to_string()
}

async fn read_input() -> Result<CLIMessage> {
    let tokens = read_line().await
        .split_ascii_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let mut tokens = tokens.into_iter();

    let Some(first_token) = tokens.next() else {
        return Err(Error::CLIError);
    };

    match first_token.as_str() {
        "transaction" => {
            return read_transaction(&mut tokens).await.map(|t| CLIMessage::PostTransaction(t))
        }
        "balance" => {
            let public_key = read_public_key_pem(tokens.next().ok_or(Error::CLIError)?, WALLETS.clone())?;
            return Ok(CLIMessage::CheckBalance(public_key));
        }
        _ => return Err(Error::CLIError),
    }
}

async fn read_transaction(tokens: &mut impl Iterator<Item = String>) -> Result<Transaction> {
    let Some(amount_token) = tokens.next() else {
        return Err(Error::CLIError);
    };

    let amount: u64 = amount_token.parse().map_err(|_| Error::CLIError)?;

    let receiver = read_public_key_pem(tokens.next().ok_or(Error::CLIError)?, WALLETS.clone())?;

    // we request the seed phrase from the user
    println!("Please enter your seed phrase to authenticate the transaction:");
    let seed_phrase = Zeroizing::new(read_line().await);
    let sk = key_from_seedphrase(&seed_phrase)?;
    println!("Transaction signed successfully");
    Ok(Transaction::new(
        sk.to_public_key().into(),
        receiver.into(),
        &sk.into(),
        amount,
    ))
}

fn read_public_key_pem(name: String, wallets_dir: String) -> Result<RsaPublicKey> {
    let dir = (wallets_dir + "/" + &name) + ".pem";
    println!("{dir}");
    let pem = std::fs::read_to_string(dir).map_err(|_| Error::CLIError)?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(|_| Error::CLIError)
}

pub fn key_from_seedphrase(seedphrase: &Zeroizing<String>) -> Result<RsaPrivateKey> {
    Mnemonic::validate(&seedphrase, Language::English).map_err(|_| Error::CLIError)?;
    let mnemonic = Mnemonic::from_phrase(seedphrase.as_str(), Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let seed_array = *array_ref!(seed.as_bytes(), 0, 32);
    let mut rng = ChaCha20Rng::from_seed(seed_array);
    RsaPrivateKey::new(&mut rng, 2048).map_err(|_| Error::CLIError)
}

// a function to run the command line interface as a separate task
pub fn run_cli(client_tx: Sender<ClientMessage>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let message: Result<_> = read_input().await;
            let client_tx = client_tx.clone(); // this is a cheap clone
            
            // we need this task otherwise the reading will block the sending 
            let send_task = async move { 
            match message {
                Ok(m) => {
                        client_tx.send(m.into()).await.unwrap();
                    }
                    Err(_) => {
                        println!("Invalid input");
                    }
                }
            };
            tokio::spawn(send_task);
        };
    });
}
