use std::hash::Hash;

use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::signature::RandomizedSigner;
use rsa::signature::Verifier;
use rsa::{
    pss::{Signature, SigningKey},
    sha2::{Digest, Sha256},
};
use serde::{Deserialize, Serialize};

use crate::{Address, Timeslot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub(super) from: Address,
    pub(super) to: Address,
    pub(super) amount: u64,
    pub(super) signature: Signature,
    pub(super) hash: [u8; 32],
}

impl Transaction {
    pub fn new(
        from: Address,
        to: Address,
        sk: &SigningKey<Sha256>,
        amount: u64,
    ) -> Self {
        let fields_string = Self::combine_fields_to_string(&from, &to, amount);
        let mut rng = thread_rng();
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);
        let mut hasher = Sha256::new();
        hasher.update(signature.to_string()); 
        // we hash the signature as well, since we sign with RNG we have a unique hash 
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();

        Self {
            from,
            to,
            amount,
            signature,
            hash,
        }
    }

    fn combine_fields_to_string(
        from: &Address,
        to: &Address,
        amount: u64,
    ) -> String {
        let hexify = |k: &Address| hex::encode(k.to_pkcs1_der().unwrap().as_bytes());
        format!("{:?}{:?}{}", hexify(from), hexify(to), amount)
    }

    pub fn verify_signature(&self) -> bool {
        let fields_string =
            Self::combine_fields_to_string(&self.from, &self.to, self.amount);
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let fields_hash: [u8; 32] = hasher.finalize().try_into().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(self.signature.to_string()); 
        // we hash the signature as well, since we sign with RNG we have a unique hash 
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();

        hash == self.hash && self.from.verify(&fields_hash, &self.signature).is_ok()
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Transaction {}

impl Hash for Transaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}