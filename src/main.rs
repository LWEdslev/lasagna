use rand::{thread_rng, SeedableRng};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pss::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const TRANSACTION_FEE: u64 = 1;
const BLOCK_REWARD: u64 = 50;
const ROOT_AMOUNT: u64 = 300;

type Timeslot = u64;
type Address = VerifyingKey<Sha256>;

fn generate_keypair() -> (SigningKey<Sha256>, VerifyingKey<Sha256>) {
    let mut rng = thread_rng();

    #[cfg(not(feature = "small_key"))]
    const BITS: usize = 2048;
    #[cfg(feature = "small_key")]
    const BITS: usize = 1024;

    let signing_key = SigningKey::random(&mut rng, BITS).unwrap();
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

fn main() {
    let (sk, vk) = generate_keypair();
    let sk_string = serde_json::to_string(&sk).unwrap();
    let deser_sk: SigningKey<Sha256> = serde_json::from_str(&sk_string).unwrap();

    let vk_string = serde_json::to_string(&vk).unwrap();
    let deser_vk: VerifyingKey<Sha256> = serde_json::from_str(&vk_string).unwrap();

    let bytes = b"Hello world";
    let signature = sk.sign_with_rng(&mut thread_rng(), bytes);
    let signature_string = serde_json::to_string(&signature).unwrap();
    let deser_signature = serde_json::from_str(&signature_string).unwrap();
    assert_eq!(signature, deser_signature);

    /*let instant = Instant::now();
    let (sk1, vk1) = generate_keypair();
    let (_, vk2) = generate_keypair();
    println!("2x Key-gen time {} ms", instant.elapsed().as_millis());
    let trans = Transaction::new(vk1.clone(), vk2.clone(), &sk1, 50, 0);
    println!("Transaction creation time {} ms", instant.elapsed().as_millis());

    assert!(trans.verify_signature());
    println!("Transaction verification time {} ms", instant.elapsed().as_millis());

    let trans = Transaction::new(vk2.clone(), vk1.clone(), &sk1, 50, 0);

    assert!(!trans.verify_signature());

    let block = Block::new(0, [0; 32], vk1.clone(), Vec::new(), &sk1);
    assert!(block.verify_signature());

    let block = Block::new(0, [0; 32], vk2.clone(), Vec::new(), &sk1);
    assert!(!block.verify_signature());

    println!("Total time {} ms", instant.elapsed().as_millis());*/
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    id: uuid::Uuid,
    from: Address,
    to: Address,
    amount: u64,
    timeslot: Timeslot,
    signature: Signature,
}

impl Transaction {
    pub fn new(
        from: Address,
        to: Address,
        sk: &SigningKey<Sha256>,
        amount: u64,
        timeslot: Timeslot,
    ) -> Self {
        let id = uuid::Uuid::new_v4();
        let fields_string = Self::combine_fields_to_string(&from, &to, amount, &timeslot);
        let mut rng = thread_rng();
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);

        Self {
            id,
            from,
            to,
            amount,
            timeslot,
            signature,
        }
    }

    fn combine_fields_to_string(
        from: &Address,
        to: &Address,
        amount: u64,
        timeslot: &Timeslot,
    ) -> String {
        format!("{:?}{:?}{}{}", from, to, amount, timeslot)
    }

    pub fn verify_signature(&self) -> bool {
        let fields_string =
            Self::combine_fields_to_string(&self.from, &self.to, self.amount, &self.timeslot);
        let mut hasher = Sha256::new();
        hasher.update(fields_string);
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        self.from.verify(&hash, &self.signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    timeslot: Timeslot,
    prev_hash: [u8; 32],
    depth: u64,
    winner: Address,
    transactions: Vec<Transaction>,
    draw: Draw,
    signature: Signature,
    hash: [u8; 32],
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
        let fields_string =
            Block::combine_fields_to_string(&timeslot, &prev_hash, depth, &winner, &transactions);
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        let signature = sk.sign_with_rng(&mut rng, &hash);
        let draw = Draw::new(timeslot, winner.clone(), &sk, prev_hash);
        Self {
            timeslot,
            prev_hash,
            depth,
            winner,
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
            &self.winner,
            &self.transactions,
        );
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        hash == self.hash && self.winner.verify(&hash, &self.signature).is_ok()
    }

    fn verify_winner(&self) -> bool {
        todo!("check draw and winner and signature")
    }

    fn combine_fields_to_string(
        timeslot: &Timeslot,
        prev_hash: &[u8; 32],
        depth: u64,
        winner: &Address,
        transactions: &Vec<Transaction>,
    ) -> String {
        let transactions = serde_json::to_string(transactions).unwrap();
        format!("{timeslot}{prev_hash:?}{depth}{winner:?}{transactions}")
    }

    fn increment_timestamp(&mut self) {
        self.timeslot += 1;
    }

    fn set_draw(&mut self, sk: &SigningKey<Sha256>) {
        self.draw = Draw::new(self.timeslot, self.winner.clone(), sk, self.prev_hash);
    }
    
    fn sign_and_rehash(&mut self, sk: &SigningKey<Sha256>) {
        let fields_string = Block::combine_fields_to_string(
            &self.timeslot,
            &self.prev_hash,
            self.depth,
            &self.winner,
            &self.transactions,
        );
        let mut hasher = Sha256::new();
        hasher.update(fields_string.as_bytes());
        let hash: [u8; 32] = hasher.finalize().try_into().unwrap();
        self.hash = hash;
        self.signature = sk.sign_with_rng(&mut thread_rng(), &hash);
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    value: BigUint,
    timeslot: Timeslot,
    signature: Signature,
    signed_by: Address,
    prev_hash: [u8; 32],
}

impl Draw {
    pub fn new(timeslot: Timeslot, vk: Address, sk: &SigningKey<Sha256>, prev_hash: [u8; 32]) -> Self {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    map: HashMap<RsaPublicKey, u64>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn add_acount_if_absent(&mut self, account: &RsaPublicKey) {
        if !self.map.contains_key(&account) {
            self.map.insert(account.clone(), 0);
        }
    }

    pub fn get_balance(&self, account: &RsaPublicKey) -> u64 {
        *self.map.get(account.into()).unwrap()
    }

    pub fn reward_winner(&mut self, winner: &RsaPublicKey, amount: u64) {
        self.add_acount_if_absent(winner);
        let balance = self.map.get_mut(winner).unwrap();
        *balance += amount;
    }

    pub fn process_transaction(&mut self, transaction: &Transaction) -> bool {
        if !transaction.verify_signature() {
            return false;
        };
        if transaction.amount < TRANSACTION_FEE {
            return false;
        };
        let from: RsaPublicKey = transaction.from.clone().into();
        let to: RsaPublicKey = transaction.to.clone().into();
        let amount = transaction.amount;
        self.add_acount_if_absent(&from);
        self.add_acount_if_absent(&to);

        let from_balance = self.map.get_mut(&from).unwrap();

        if *from_balance < amount + TRANSACTION_FEE {
            return false;
        }

        *from_balance -= amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(&to.into()).unwrap();

        *to_balance += amount;

        true
    }

    /// Reverse the transaction
    pub fn rollback_transaction(&mut self, transaction: &Transaction) {
        let from: RsaPublicKey = transaction.from.clone().into();
        let to: RsaPublicKey = transaction.to.clone().into();
        let amount = transaction.amount;

        let from_balance = self.map.get_mut(&from).unwrap();

        *from_balance += amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(&to.into()).unwrap();
        *to_balance -= amount;
    }

    pub fn get_total_money_in_ledger(&self) -> u64 {
        self.map.values().sum()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Blockchain {
    blocks: Vec<HashMap<[u8; 32], Block>>, // at index i all blocks at depth i exists in a map from their hash to the block TODO encapsulate
    best_path_head: ([u8; 32], u64), // the hash and depth of the head of the current best path
    ledger: Ledger,                  // this should follow the best_path_heads state
    root_accounts: Vec<RsaPublicKey>,
    orphans: HashMap<[u8; 32], Vec<Block>>, // maps from the parent that they have which is not in blocks TODO encapsulate this
    transaction_buffer: Vec<Transaction>,
}

impl Blockchain {
    pub fn start(root_accounts: Vec<RsaPublicKey>, any_sk: &SigningKey<Sha256>) -> Self {
        let mut hasher = Sha256::new();
        for ra in root_accounts.iter() {
            hasher.update(ra.to_pkcs1_der().unwrap().as_bytes());
        }

        let seed_hash: [u8; 32] = hasher.finalize().into();

        let block = Block::new(
            0,
            seed_hash,
            0,
            root_accounts.get(0).unwrap().clone().into(),
            Vec::new(),
            any_sk,
        );
        let hash = block.hash.clone();
        let mut map = HashMap::new();
        map.insert(hash.clone(), block.clone());
        let mut ledger = Ledger::new();
        for root_account in root_accounts.iter() {
            ledger.reward_winner(root_account, ROOT_AMOUNT);
        }

        let blocks = vec![map];

        Self {
            blocks,
            best_path_head: (hash, 0),
            ledger,
            root_accounts,
            orphans: HashMap::new(),
            transaction_buffer: Vec::new(),
        }
    }

    /// Returns whether the new block extends the best path
    pub fn add_block(&mut self, block: Block) -> bool {
        if !block.verify_signature() {
            dbg!("signature invalid");
            return false;
        }
        let depth = block.depth as usize;
        while depth >= self.blocks.len() {
            // create empty hashmaps if the block is in the future, this will usually just be done once
            self.blocks.push(HashMap::new());
        }
        let get_parent = |parent_hash: [u8; 32]| {
            let map = self.blocks.get(depth - 1)?;
            map.get(&parent_hash)
        };

        let parent_hash = block.prev_hash;
        let parent_block = get_parent(block.prev_hash);
        let Some(_) = parent_block else {
            // the parent does not exist yet so we are an orphan
            if let Some(orphans_of_prev) = self.orphans.get_mut(&block.prev_hash) {
                orphans_of_prev.push(block);
            } else {
                self.orphans.insert(block.prev_hash, vec![block]);
            }
            println!("unable to find parent block");
            return false;
        };

        // clone the stuff we need later
        let block_hash = block.hash.clone();
        // we add ourself
        self.blocks
            .get_mut(depth)
            .expect("unreachable")
            .insert(block.hash.clone(), block.clone());

        // we check if this is the new best path
        let (old_best_path, old_depth) = self.best_path_head;

        if depth > old_depth as _ {
            // this is definetely the new best path
            self.best_path_head = (block_hash, depth as _);

            // rollback if we changed branch
            if old_best_path != parent_hash {
                println!("rollback 1");
                self.rollback((old_best_path, old_depth), (block_hash, depth as _));
            } else {
                self.proccess_transactions(&block.transactions);
            }
        } else if depth == self.best_path_head.1 as usize {
            println!("equal depth");
            // the tiebreaker is who has the lexicographically highest hex hash
            // TODO add timestamp and len(transactions) tiebreaker
            let new_hash = hex::encode(block_hash.clone());
            let curr_best_hash = hex::encode(self.best_path_head.0.clone());

            if let std::cmp::Ordering::Greater = new_hash.cmp(&curr_best_hash) {
                self.best_path_head = (block_hash, depth as _);
                // we always have to rollback in this case
                println!("rollback 2");
                self.rollback((old_best_path, old_depth), (block_hash, depth as _));
            }
        }

        // we check if we have any orphans, if we do we must add them after ourself
        if let Some(orphans) = self.orphans.remove(&block_hash) {
            for orphan in orphans {
                println!("added orphan");
                self.add_block(orphan.clone());
            }
        }

        // return whether the best_path has been updated
        old_best_path != self.best_path_head.0
    }

    pub fn rollback(&mut self, from: ([u8; 32], u64), to: ([u8; 32], u64)) {
        let get_block = |hash: &[u8; 32], depth: u64| {
            self.blocks
                .get(depth as usize)
                .and_then(|m| m.get(hash))
                .unwrap()
        };

        let mut from_ptr = get_block(&from.0, from.1);
        let mut to_ptr = get_block(&to.0, to.1);
        let mut track_stack = Vec::new();
        while from_ptr != to_ptr {
            track_stack.push((to_ptr.hash, to_ptr.depth));
            if to_ptr.depth == 1 && from_ptr.depth == 1 {
                if to_ptr.prev_hash == from_ptr.prev_hash {
                    for t in from_ptr.transactions.iter() {
                        self.ledger.rollback_transaction(t);
                        println!("rolling back t");
                    }
                    break; // we have reached the root
                }
            }
            let (to_parent_hash, to_parent_depth) = (&to_ptr.prev_hash, to_ptr.depth - 1);
            let old_to_ptr_depth = to_ptr.depth;
            to_ptr = get_block(to_parent_hash, to_parent_depth);

            if old_to_ptr_depth == from_ptr.depth {
                // to_depth is always >= from_depth so we have to ensure that to goes back first
                // we roll back the transactions on the from path
                for t in from_ptr.transactions.iter() {
                    self.ledger.rollback_transaction(t);
                }

                let (from_parent_hash, from_parent_depth) =
                    (&from_ptr.prev_hash, from_ptr.depth - 1);
                from_ptr = get_block(from_parent_hash, from_parent_depth);
            }
        }

        // so now the track_stack should be the path from_ptr/to_ptr to the from/to hash
        // so we perform the new transactions
        while let Some((hash, depth)) = track_stack.pop() {
            let block = get_block(&hash, depth);
            for t in block.transactions.iter() {
                self.ledger.process_transaction(t); // an optimization is not verifying the transaction here
            }
        }
    }

    /// Simply checks if you've won
    pub fn stake(&self, block: &Block, wallet: &RsaPublicKey) -> bool {
        let balance = self.ledger.get_balance(&wallet);
        let total_money = self.ledger.get_total_money_in_ledger();
        
        let hardness = BigUint::from(2800u64) * BigUint::from(10u64).pow(73);

        // We win if we have a good draw and a big enough fraction of the money
        block.draw.value.clone() * (BigUint::from(balance)) > hardness * BigUint::from(total_money)
    }

    fn proccess_transactions(&mut self, transactions: &Vec<Transaction>) {
        for t in transactions.iter() {
            self.ledger.process_transaction(t); // an optimization is not verifying the transaction here
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_draw_verify() {
        let (sk, vk) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let draw = Draw::new(0, vk.clone(), &sk, [0; 32]);
        assert!(draw.verify());

        let draw = Draw::new(0, vk2.clone(), &sk, [0; 32]);
        assert!(!draw.verify());
    }

    #[test]
    fn test_transaction_verify() {
        let (sk, vk) = generate_keypair();

        let from = vk.clone();
        let to = generate_keypair().1;
        let amount = 50;
        let timeslot: Timeslot = 0;
        let transaction = Transaction::new(from.clone(), to.clone(), &sk, amount, timeslot);

        assert!(transaction.verify_signature());
    }

    #[test]
    fn test_block_verify() {
        let (sk, vk) = generate_keypair();

        let from = vk.clone();
        let to = generate_keypair().1;
        let amount = 50;
        let timeslot: Timeslot = 0;
        let transaction = Transaction::new(from.clone(), to.clone(), &sk, amount, timeslot);
        let transactions = vec![transaction];

        // Create a block
        let timeslot = 0;
        let prev_hash = [0; 32];
        let winner = vk.clone();
        let block = Block::new(
            timeslot,
            prev_hash,
            0,
            winner.clone(),
            transactions.clone(),
            &sk,
        );

        assert!(block.verify_signature());
    }

    #[test]
    fn test_ledger() {
        let (sk, vk) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();

        let from = vk.clone();
        let from_rsa: RsaPublicKey = from.clone().into();
        let to = vk2.clone();
        let to_rsa: RsaPublicKey = to.clone().into();
        let transaction = Transaction::new(from.clone(), to.clone(), &sk, 50, 0);

        let mut ledger = Ledger::new();
        ledger.reward_winner(&from_rsa, 102);
        assert!(ledger.process_transaction(&transaction));

        assert_eq!(ledger.get_balance(&from_rsa), 51);
        assert_eq!(ledger.get_balance(&to_rsa), 50);

        let transaction = Transaction::new(from.clone(), to.clone(), &sk, 50, 0);
        assert!(ledger.process_transaction(&transaction));

        assert_eq!(ledger.get_balance(&from_rsa), 0);
        assert_eq!(ledger.get_balance(&to_rsa), 100);

        ledger.rollback_transaction(&transaction);
        assert_eq!(ledger.get_balance(&from_rsa), 51);
        assert_eq!(ledger.get_balance(&to_rsa), 50);

        assert!(ledger.process_transaction(&transaction));
        assert!(!ledger.process_transaction(&transaction));
        ledger.rollback_transaction(&transaction);

        // ensure that the both have enough balance
        ledger.reward_winner(&from_rsa, 100);
        ledger.reward_winner(&vk3.clone().into(), 100);

        let transaction = Transaction::new(vk3.clone(), from.clone(), &sk, 50, 0);

        assert!(!ledger.process_transaction(&transaction)); // invalid signature
    }

    #[test]
    fn test_blockchain_rollback() {
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        let (_, vk4) = generate_keypair();

        // _b1_1 refers to branch 1, depth 1

        let mut blockchain = Blockchain::start(
            vec![
                vk1.clone().into(),
                vk2.clone().into(),
                vk3.clone().into(),
                vk4.clone().into(),
            ],
            &sk1,
        );

        let transaction_b1_1 = Transaction::new(vk1.clone(), vk3.clone(), &sk1, 10, 1);
        let transaction_b1_2 = Transaction::new(vk1.clone(), vk3.clone(), &sk1, 10, 2);

        let transaction_b2_1 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 1);

        let block_b1_1 = Block::new(
            1,
            blockchain.best_path_head.0,
            1,
            vk2.clone(),
            vec![transaction_b1_1],
            &sk2,
        );
        assert!(block_b1_1.verify_signature());
        let block_b2_1 = Block::new(
            1,
            blockchain.best_path_head.0,
            1,
            vk2.clone(),
            vec![transaction_b2_1],
            &sk2,
        );
        assert!(block_b2_1.verify_signature());
        let block_b1_2 = Block::new(
            2,
            block_b1_1.hash,
            2,
            vk2.clone(),
            vec![transaction_b1_2],
            &sk2,
        );
        assert!(block_b1_2.verify_signature());

        blockchain.blocks.push(HashMap::new());

        assert!(blockchain.add_block(block_b2_1.clone())); // this is always true, since we increase the depth
        if blockchain.add_block(block_b1_1.clone()) {
            // in case of a rollback
            assert_eq!(
                *blockchain.ledger.map.get(&vk1.clone().into()).unwrap(),
                ROOT_AMOUNT - 10 - TRANSACTION_FEE
            )
        } else {
            // in case of no rollback so still b2_1 state
            assert_eq!(
                *blockchain.ledger.map.get(&vk1.clone().into()).unwrap(),
                ROOT_AMOUNT - 20 - TRANSACTION_FEE
            )
        }

        assert!(blockchain.add_block(block_b1_2.clone())); // this will always be true, it may or may not cause a rollback
                                                           // so now the ledger follows b1_2,
                                                           // if we then add b2_2 and b2_3 there must be a rollback
        let transaction_b2_2 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 1);
        let block_b2_2 = Block::new(
            2,
            block_b2_1.hash,
            2,
            vk2.clone(),
            vec![transaction_b2_2],
            &sk2,
        );
        let transaction_b2_3 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 1);
        let block_b2_3 = Block::new(
            3,
            block_b2_2.hash,
            3,
            vk2.clone(),
            vec![transaction_b2_3],
            &sk2,
        );
        blockchain.add_block(block_b2_2);
        assert!(blockchain.add_block(block_b2_3));

        // now we check the ledgers state
        assert_eq!(
            *blockchain.ledger.map.get(&vk1.clone().into()).unwrap(),
            ROOT_AMOUNT - 60 - 3 * TRANSACTION_FEE
        );
        assert_eq!(
            *blockchain.ledger.map.get(&vk4.clone().into()).unwrap(),
            ROOT_AMOUNT + 60
        );
    }

    #[test]
    fn test_stake() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        
        for _ in 0..10 {
            let (sk, vk) = generate_keypair();
            let mut blockchain = Blockchain::start(vec![vk.clone().into(), vk1.clone().into(), vk2.clone().into(), vk3.clone().into()], &sk);

            let mut block = Block::new(0, blockchain.best_path_head.0, 1, vk.clone().into(), Vec::new(), &sk);
            let mut has_won = blockchain.stake(&block, &vk.clone().into());
            let mut tries = 0;
            while !has_won {
                block.increment_timestamp();
                block.set_draw(&sk);
                has_won = blockchain.stake(&block, &vk.clone().into());
                tries += 1;
            }
            
            println!("Tries: {}", tries);
            block.sign_and_rehash(&sk);
            assert!(blockchain.add_block(block));
        }


    }

    #[test]
    fn test_orphanage() {}
}
