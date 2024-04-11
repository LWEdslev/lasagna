use std::collections::HashSet;

use crate::{draw::Draw, transaction::Transaction, Address, Timeslot};
use rand::thread_rng;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier;
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pss::{Signature, SigningKey},
    sha2::{Digest, Sha256},
    signature::RandomizedSigner,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub(super) timeslot: Timeslot,
    pub prev_hash: [u8; 32],
    pub(super) depth: u64,
    pub(super) transactions: Vec<Transaction>,
    pub(super) draw: Draw,
    pub(super) signature: Signature,
    pub hash: [u8; 32],
}

impl Block {
    pub fn new(
        timeslot: Timeslot,
        prev_hash: [u8; 32],
        depth: u64,
        winner: Address,
        transactions: Vec<Transaction>,
        sk: &SigningKey<Sha256>,
    ) -> Self {
        let mut rng = thread_rng();
        let draw = Draw::new(timeslot, winner.clone(), &sk, prev_hash);
        let fields_string =
            Block::combine_fields_to_string(&timeslot, &prev_hash, depth, &draw, &transactions);
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);
        Self {
            timeslot,
            prev_hash,
            depth,
            transactions,
            draw,
            signature,
            hash,
        }
    }

    pub fn verify_signature(&self) -> bool {
        let fields_string = Block::combine_fields_to_string(
            &self.timeslot,
            &self.prev_hash,
            self.depth,
            &self.draw,
            &self.transactions,
        );
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        hash == self.hash && self.draw.signed_by.verify(&hash, &self.signature).is_ok()
    }

    fn verify_winner(&self) -> bool {
        if !self.draw.verify() {
            return false;
        }
        if self.draw.timeslot != self.timeslot {
            return false;
        }
        true
    }

    fn verify_transactions(&self, previous_transactions: &HashSet<[u8; 32]>) -> bool {
        self.transactions.iter().all(|t| {
            t.verify_signature()
                && t.timeslot < self.timeslot
                && !previous_transactions.contains(&t.hash)
        })
    }

    pub(super) fn verify_all(&self, previous_transactions: &HashSet<[u8; 32]>) -> bool {
        let signature = self.verify_signature();
        let transactions = self.verify_transactions(previous_transactions);
        let winner = self.verify_winner();
        println!("s {signature}, t {transactions}, w {winner}");
        signature && transactions && winner
    }

    pub(super) fn verify_genesis(&self, root_accounts: &Vec<RsaPublicKey>) -> bool {
        let mut hasher = Sha256::new();
        for ra in root_accounts.iter() {
            hasher.update(ra.to_pkcs1_der().unwrap().as_bytes());
        }

        let seed_hash: [u8; 32] = hasher.finalize().into();
        self.transactions.is_empty() && self.verify_signature() && seed_hash == self.prev_hash
    }

    // this should be replaced with a hashing function
    fn combine_fields_to_string(
        timeslot: &Timeslot,
        prev_hash: &[u8; 32],
        depth: u64,
        draw: &Draw,
        transactions: &Vec<Transaction>,
    ) -> String {
        // we can just use the hashes and the signatures of these to save a lot of space while preserving safety
        let transactions =
            serde_json::to_string(&transactions.iter().map(|t| t.hash).collect::<Vec<_>>())
                .unwrap();
        let draw = hex::encode(draw.signature.to_bytes());
        format!("{timeslot}{prev_hash:?}{depth}{draw}{transactions}")
    }

    pub fn increment_timeslot(&mut self) {
        self.timeslot += 1;
    }

    pub(super) fn set_draw(&mut self, sk: &SigningKey<Sha256>) {
        self.draw = Draw::new(
            self.timeslot,
            self.draw.signed_by.clone(),
            sk,
            self.prev_hash,
        );
    }

    pub(super) fn sign_and_rehash(&mut self, sk: &SigningKey<Sha256>) {
        let fields_string = Block::combine_fields_to_string(
            &self.timeslot,
            &self.prev_hash,
            self.depth,
            &self.draw,
            &self.transactions,
        );
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        self.hash = hash;
        self.signature = sk.sign_with_rng(&mut thread_rng(), &hash);
    }

    pub(super) fn rehash(&mut self) {
        let fields_string = Block::combine_fields_to_string(
            &self.timeslot,
            &self.prev_hash,
            self.depth,
            &self.draw,
            &self.transactions,
        );
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        self.hash = hash;
    }

    // Tiebreak
    pub(super) fn is_better_than(&self, other: &Block) -> bool {
        // Tiebreak 1, earliest timeslot
        if self.timeslot < other.timeslot {
            return true;
        } else if self.timeslot > other.timeslot {
            return false;
        }
        // Tiebreak 2, most transactions
        if self.transactions.len() > other.transactions.len() {
            return true;
        } else if self.transactions.len() < other.transactions.len() {
            return false;
        }

        // Tiebreak 3, lexicographically greatest hash
        let self_hash = hex::encode(self.hash.clone());
        let other_hash = hex::encode(other.hash.clone());

        if let std::cmp::Ordering::Greater = self_hash.cmp(&other_hash) {
            return true;
        }
        false
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}
