use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use block::Block;
use blockchain::{Blockchain, BlockchainError};

use cli::CliPreTransaction;
use draw::Draw;
use ledger::Ledger;
use num_bigint::BigUint;
use rand::thread_rng;

use rsa::{
    sha2::Sha256,
    RsaPrivateKey, RsaPublicKey,
};
use seeding_mechanism::MIN_SEED_AGE;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use transaction::Transaction;
pub mod clock_watch;
pub mod block;
pub mod blockchain;
pub mod blockchain_actor;
pub mod cli;
pub mod client;
pub mod draw;
pub mod ledger;
pub mod network_actor;
pub mod pippi;
pub mod transaction;
pub mod seeding_mechanism;

pub const TRANSACTION_FEE: u64 = 1;
pub const BLOCK_REWARD: u64 = 50;
pub const ROOT_AMOUNT: u64 = 300;
#[cfg(not(test))]
pub const SLOT_LENGTH: u128 = 10_000_000;
#[cfg(test)]
pub const SLOT_LENGTH: u128 = 1; // 0.001 millisecond for testing

pub(crate) type Timeslot = u64;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref ADDR: SocketAddr = {
        println!("Enter your peer's address (Example 127.0.0.1:8080):");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        SocketAddr::from_str(buf.trim()).expect("unable to parse address")
    };

    pub static ref SEED_ADDR: SocketAddr = {
        println!("Enter a seed nodes address (Example 127.0.0.1:8081):");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        SocketAddr::from_str(buf.trim()).expect("unable to parse address")
    };

    pub static ref WALLETS: PathBuf = {
        println!("Enter path to wallet pems (Example ./wallets):");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        let path = Path::new(buf.trim()).to_owned();
        if !path.exists() {
            panic!("{path:?} does not exist")
        }
        path
    };

    pub static ref ROOTS: PathBuf = {
        println!("Enter path to root account pems (Example ./roots):");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        let path = Path::new(buf.trim()).to_owned();
        if !path.exists() {
            panic!("{path:?} does not exist")
        }
        path
    };
}

pub fn generate_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = thread_rng();

    #[cfg(not(feature = "small_key"))]
    const BITS: usize = 2048;
    #[cfg(feature = "small_key")]
    const BITS: usize = 1024;

    let sk = RsaPrivateKey::new(&mut rng, BITS).unwrap();
    let pk = sk.to_public_key();
    (sk, pk)
}

fn is_winner(ledger: &Ledger, draw: Draw, wallet: &RsaPublicKey, depth: u64) -> bool {
    #[cfg(feature = "always_win")]
    return true;

    let Some(account_published_at) = ledger.published_accounts.get(wallet) else  {
        println!("account not published");
        return false // account has not been published
    };

    let account_age = depth - account_published_at;

    if account_age < MIN_SEED_AGE && *account_published_at != 0 { 
        println!("account too young");
        return false
     }

    let balance = BigUint::from(ledger.get_balance(wallet));
    let total_money = ledger.get_total_money_in_ledger();

    let max_hash = BigUint::from(2u64).pow(256);

    // the entire network has a total 10% chance of beating this at a given timeslot
    let hardness = BigUint::from(10421u64) * (BigUint::from(10u64).pow(73));

    // we must map the draw value which is in [0, 2^256] to [0, h + c(2^256 - h)] where h is hardness and c is the ratio of money we have
    // we can map this by multiplying the draw with (h + c(2^256 - h))/(2^256)
    // we can describe c as balance/total_money. Therefore we can multiply total_money to the hardness and write the multiplication factor as:
    let mult_factor =
        (hardness.clone() * total_money) + (balance * (max_hash.clone() - hardness.clone()));

    // We win if we have a good draw and a big enough fraction of the money
    draw.value.clone() * mult_factor > hardness * total_money * max_hash.clone()
}

pub fn get_unix_timestamp() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pkcs1v15Signature(Vec<u8>);

impl Pkcs1v15Signature {
    pub fn sign(sk: &RsaPrivateKey, hashed_data: &[u8]) -> Result<Pkcs1v15Signature> {
        sk.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), hashed_data)
            .map(Pkcs1v15Signature)
            .map_err(|_| Error::Pkcs1v15Error)
    }

    pub fn verify(&self, vk: &RsaPublicKey, hashed_data: &[u8]) -> Result<()> {
        vk.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), hashed_data, &self.0)
            .map_err(|_| Error::Pkcs1v15Error)
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PssSignature(Vec<u8>);

impl PssSignature {
    pub fn sign(sk: &RsaPrivateKey, hashed_data: &[u8]) -> Result<PssSignature> {
        sk.sign_with_rng(&mut thread_rng(), rsa::Pss::new::<Sha256>(), hashed_data)
            .map(PssSignature)
            .map_err(|_| Error::PssError)
    }

    pub fn verify(&self, vk: &RsaPublicKey, hashed_data: &[u8]) -> Result<()> {
        vk.verify(rsa::Pss::new::<Sha256>(), hashed_data, &self.0)
            .map_err(|_| Error::PssError)
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

// messages to the client
#[derive(Clone, Debug)]
pub enum ClientMessage {
    Won(Block),
    BalanceOf(RsaPublicKey, u64),
    External(ExternalMessage),
    CLI(CLIMessage),
    Ping,
}

/// Messages received on the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExternalMessage {
    Bootstrap(Blockchain), // if we need a blockchain to start off on we take this one
    BootstrapReqFrom(SocketAddr), // someone needs a blockchain
    BroadcastTransaction(Transaction),
    BroadcastBlock(Block), // a won block
}

impl From<ExternalMessage> for ClientMessage {
    fn from(value: ExternalMessage) -> Self {
        ClientMessage::External(value)
    }
}

// messages from the CLI to the client
#[derive(Clone, Debug)]
pub enum CLIMessage {
    PostTransaction(CliPreTransaction),
    CheckBalance(RsaPublicKey),
}

impl From<CLIMessage> for ClientMessage {
    fn from(value: CLIMessage) -> Self {
        ClientMessage::CLI(value)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Error occured in the network actor")]
    NetworkError,
    #[error("Error occured when using the CLI")]
    CLIError,
    #[error("Invalid pem")]
    InvalidPem,
    #[error("pkcs1v15 error")]
    Pkcs1v15Error,
    #[error("pss error")]
    PssError,
    #[error("Internal Blockchain error")]
    BlockchainError(BlockchainError),
}

pub(crate) fn calculate_timeslot(start_time: u128) -> Timeslot {
    #[cfg(feature = "max_timeslot")]
    return u64::MAX;

    let now = crate::get_unix_timestamp();
    let start = start_time;
    let timeslot = (now - start) / SLOT_LENGTH;
    timeslot as _
}

pub type Result<T> = std::result::Result<T, Error>;