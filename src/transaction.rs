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
    pub(super) timeslot: Timeslot,
    pub(super) signature: Signature,
    pub(super) hash: [u8; 32],
}

impl Transaction {
    pub fn new(
        from: Address,
        to: Address,
        sk: &SigningKey<Sha256>,
        amount: u64,
        timeslot: Timeslot,
    ) -> Self {
        let fields_string = Self::combine_fields_to_string(&from, &to, amount, &timeslot);
        let mut rng = thread_rng();
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);

        Self {
            from,
            to,
            amount,
            timeslot,
            signature,
            hash,
        }
    }

    fn combine_fields_to_string(
        from: &Address,
        to: &Address,
        amount: u64,
        timeslot: &Timeslot,
    ) -> String {
        let hexify = |k: &Address| hex::encode(k.to_pkcs1_der().unwrap().as_bytes());
        format!("{:?}{:?}{}{}", hexify(from), hexify(to), amount, timeslot)
    }

    pub fn verify_signature(&self) -> bool {
        let fields_string =
            Self::combine_fields_to_string(&self.from, &self.to, self.amount, &self.timeslot);
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        hash == self.hash && self.from.verify(&hash, &self.signature).is_ok()
    }
}
