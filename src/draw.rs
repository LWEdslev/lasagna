use num_bigint::BigUint;
use rand::{thread_rng, SeedableRng};
use rsa::{pkcs1v15, pss::{Signature, SigningKey}, sha2::{Digest, Sha256}, signature::RandomizedSigner, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use rsa::signature::Verifier;
use rsa::signature::SignatureEncoding;
use crate::{Address, Timeslot};
use rsa::signature::Signer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    pub(super) value: BigUint,
    pub(super) timeslot: Timeslot,
    pub(super) signature: pkcs1v15::Signature,
    pub(super) signed_by: Address,
    signed_by_pkcs1v15: pkcs1v15::VerifyingKey<Sha256>,
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
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42); // needs 
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(prev_hash);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let rsa_sk: RsaPrivateKey = sk.clone().into();
        let pkcs1v15_sk: pkcs1v15::SigningKey<Sha256> = rsa_sk.into(); // we have to use a deterministic scheme
        let signature = pkcs1v15_sk.sign(&hash);

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
            signed_by_pkcs1v15: rsa_vk.into(),
            prev_hash,
        }
    }

    pub fn verify(&self) -> bool {
        let vk = &self.signed_by_pkcs1v15;
        let timeslot = self.timeslot;
        let data = format!("Lottery{timeslot}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.prev_hash);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        vk.verify(&hash, &self.signature).is_ok()
    }
}