use num_bigint::BigUint;
use rsa::{sha2::{Digest, Sha256}, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use crate::{seeding_mechanism::SeedContent, Pkcs1v15Signature, Timeslot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    pub(super) value: BigUint,
    pub(super) timeslot: Timeslot,
    pub(super) signature: Pkcs1v15Signature,
    pub(super) signed_by: RsaPublicKey,
    pub(super) seed: SeedContent,
}

impl Draw {
    pub fn new(
        timeslot: Timeslot,
        seed: SeedContent,
        vk: RsaPublicKey,
        sk: &RsaPrivateKey,
    ) -> Self {
        let data = format!("Lottery{timeslot}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(seed.seed);
        let hash: [u8; 32] = hasher.finalize().into();
        let signature = Pkcs1v15Signature::sign(sk, &hash).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        let signature_hash: [u8; 32] = hasher.finalize().into();
        let value = BigUint::from_bytes_be(&signature_hash);

        let _rsa_vk: RsaPublicKey = vk.clone();

        Self {
            value,
            timeslot,
            signature,
            signed_by: vk,
            seed,
        }
    }

    pub fn verify(&self) -> bool {
        let vk = &self.signed_by;
        let timeslot = self.timeslot;
        let data = format!("Lottery{timeslot}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.seed.seed);
        let hash: [u8; 32] = hasher.finalize().into();
        self.signature.verify(vk, &hash).is_ok()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signature.0.clone());
        hasher.finalize().into()
    }
}