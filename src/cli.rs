use std::{fs::ReadDir, time::Duration};

use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{
    pkcs1::EncodeRsaPublicKey, pkcs8::{der::zeroize::Zeroizing, DecodePublicKey}, RsaPrivateKey, RsaPublicKey
};
use tokio::sync::mpsc::Sender;

use crate::{transaction::Transaction, CLIMessage, ClientMessage, LasseCoinError, Result};

pub(crate) fn read_line() -> String {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    line.trim().to_string()
}

fn read_input(wallets_dir: String) -> Result<CLIMessage> {
    let tokens = read_line()
        .split_ascii_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let mut tokens = tokens.into_iter();

    let Some(first_token) = tokens.next() else {
        return Err(LasseCoinError::CLIError);
    };

    match first_token.as_str() {
        "transaction" => {
            return read_transaction(&mut tokens, wallets_dir).map(|t| CLIMessage::PostTransaction(t))
        }
        "balance" => {
            let public_key = read_public_key_pem(tokens.next().ok_or(LasseCoinError::CLIError)?, wallets_dir)?;
            return Ok(CLIMessage::CheckBalance(public_key));
        }
        _ => return Err(LasseCoinError::CLIError),
    }
}

fn read_transaction(tokens: &mut impl Iterator<Item = String>, wallets_dir: String) -> Result<Transaction> {
    let Some(amount_token) = tokens.next() else {
        return Err(LasseCoinError::CLIError);
    };

    let amount: u64 = amount_token.parse().map_err(|_| LasseCoinError::CLIError)?;

    let receiver = read_public_key_pem(tokens.next().ok_or(LasseCoinError::CLIError)?, wallets_dir)?;

    // we request the seed phrase from the user
    println!("Please enter your seed phrase to authenticate the transaction:");
    let seed_phrase = Zeroizing::new(read_line());
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
    let pem = std::fs::read_to_string(dir).map_err(|_| LasseCoinError::CLIError)?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(|_| LasseCoinError::CLIError)
}

pub fn key_from_seedphrase(seedphrase: &Zeroizing<String>) -> Result<RsaPrivateKey> {
    Mnemonic::validate(&seedphrase, Language::English).map_err(|_| LasseCoinError::CLIError)?;
    let mnemonic = Mnemonic::from_phrase(seedphrase.as_str(), Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let seed_array = *array_ref!(seed.as_bytes(), 0, 32);
    let mut rng = ChaCha20Rng::from_seed(seed_array);
    RsaPrivateKey::new(&mut rng, 2048).map_err(|_| LasseCoinError::CLIError)
}

// a function to run the command line interface as a separate task
pub fn run_cli(client_tx: Sender<ClientMessage>, wallets_dir: String) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let message: Result<_> = read_input(wallets_dir.clone());
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
