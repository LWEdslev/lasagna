use num_bigint::BigUint;
use rsa::{sha2::{Digest, Sha256}, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use crate::{Pkcs1v15Signature, Timeslot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    pub(super) value: BigUint,
    pub(super) timeslot: Timeslot,
    pub(super) signature: Pkcs1v15Signature,
    pub(super) signed_by: RsaPublicKey,
    pub(super) prev_hash: [u8; 32],
}

impl Draw {
    pub fn new(
        timeslot: Timeslot,
        vk: RsaPublicKey,
        sk: &RsaPrivateKey,
        prev_hash: [u8; 32],
    ) -> Self {
        let data = format!("Lottery{timeslot}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(prev_hash);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = Pkcs1v15Signature::sign(sk, &hash).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        let signature_hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let value = BigUint::from_bytes_be(&signature_hash);

        let rsa_vk: RsaPublicKey = vk.clone().into();

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
        self.signature.verify(vk, &hash).is_ok()
    }
}