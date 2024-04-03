use num_bigint::BigUint;
use rand::thread_rng;
use rsa::{pss::{Signature, SigningKey}, sha2::{Digest, Sha256}, signature::RandomizedSigner};
use serde::{Deserialize, Serialize};
use rsa::signature::Verifier;
use rsa::signature::SignatureEncoding;
use crate::{Address, Timeslot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    pub(super) value: BigUint,
    pub(super) timeslot: Timeslot,
    pub(super) signature: Signature,
    pub(super) signed_by: Address,
    pub(super) prev_hash: [u8; 32],
}

impl Draw {
    pub fn new(
        timeslot: Timeslot,
        vk: Address,
        sk: &SigningKey<Sha256>,
        prev_hash: [u8; 32],
    ) -> Self {
        let data = format!("Lottery{timeslot}");
        let mut rng = thread_rng();
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(prev_hash);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);

        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        let signature_hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let value = BigUint::from_bytes_be(&signature_hash);

        Self {
            value,
            timeslot,
            signature,
            signed_by: vk,
            prev_hash,
        }
    }

    pub fn verify(&self) -> bool {
        let vk = &self.signed_by;
        let timeslot = self.timeslot;
        let data = format!("Lottery{timeslot}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.prev_hash);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        vk.verify(&hash, &self.signature).is_ok()
    }
}