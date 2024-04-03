use num_bigint::BigUint;
use rand::{thread_rng, SeedableRng};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pss::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

fn main() {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    from: Address,
    to: Address,
    amount: u64,
    timeslot: Timeslot,
    signature: Signature,
    hash: [u8; 32],
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
        let hexify = |k: &Address| {
            hex::encode(k.to_pkcs1_der().unwrap().as_bytes())
        };
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    timeslot: Timeslot,
    prev_hash: [u8; 32],
    depth: u64,
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

    fn verify_all(&self, previous_transactions: &HashSet<[u8; 32]>) -> bool {
        let signature = self.verify_signature();
        let transactions = self.verify_transactions(previous_transactions);
        let winner = self.verify_winner();
        println!("s {signature}, t {transactions}, w {winner}");
        signature && transactions && winner
    }

    fn verify_genesis(&self, root_accounts: &Vec<RsaPublicKey>) -> bool {
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
        let transactions = serde_json::to_string(&transactions.iter().map(|t| t.hash).collect::<Vec<_>>()).unwrap();
        let draw = hex::encode(draw.signature.to_bytes());
        format!("{timeslot}{prev_hash:?}{depth}{draw}{transactions}")
    }

    fn increment_timeslot(&mut self) {
        self.timeslot += 1;
    }

    fn set_draw(&mut self, sk: &SigningKey<Sha256>) {
        self.draw = Draw::new(
            self.timeslot,
            self.draw.signed_by.clone(),
            sk,
            self.prev_hash,
        );
    }

    fn sign_and_rehash(&mut self, sk: &SigningKey<Sha256>) {
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

    fn rehash(&mut self) {
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
    fn is_better_than(&self, other: &Block) -> bool {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Draw {
    value: BigUint,
    timeslot: Timeslot,
    signature: Signature,
    signed_by: Address,
    prev_hash: [u8; 32],
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ledger {
    map: HashMap<RsaPublicKey, u64>,
    previous_transactions: HashSet<[u8; 32]>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            previous_transactions: HashSet::new(),
        }
    }

    pub fn add_acount_if_absent(&mut self, account: &RsaPublicKey) {
        if !self.map.contains_key(&account) {
            self.map.insert(account.clone(), 0);
        }
    }

    pub fn get_balance(&self, account: &RsaPublicKey) -> u64 {
        *self.map.get(account).unwrap()
    }

    pub fn reward_winner(&mut self, winner: &RsaPublicKey, amount: u64) {
        self.add_acount_if_absent(winner);
        let balance = self.map.get_mut(winner).unwrap();
        *balance += amount;
    }

    /// Panics if the transaction has been added previously
    pub fn process_transaction(&mut self, transaction: &Transaction) -> bool {
        if !transaction.verify_signature() {
            return false;
        };
        if transaction.amount < TRANSACTION_FEE {
            return false;
        };
        let from: &RsaPublicKey = transaction.from.as_ref();
        let to: &RsaPublicKey = transaction.to.as_ref();
        let amount = transaction.amount;
        self.add_acount_if_absent(from);
        self.add_acount_if_absent(to);

        let from_balance = self.map.get_mut(from).unwrap();

        if *from_balance < amount + TRANSACTION_FEE {
            return false;
        }

        if !self.previous_transactions.insert(transaction.hash) {
            return false;
        }

        *from_balance -= amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(to).unwrap();

        *to_balance += amount;

        true
    }

    /// Reverse the transaction
    /// panics if the transaction was not performed
    pub fn rollback_transaction(&mut self, transaction: &Transaction) {
        let from: &RsaPublicKey = transaction.from.as_ref();
        let to: &RsaPublicKey = transaction.to.as_ref();
        let amount = transaction.amount;

        assert!(self.previous_transactions.remove(&transaction.hash));

        let from_balance = self.map.get_mut(from).unwrap();

        *from_balance += amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(to).unwrap();
        *to_balance -= amount;
    }

    pub fn get_total_money_in_ledger(&self) -> u64 {
        self.map.values().sum()
    }

    fn rollback_reward(&mut self, winner: &RsaPublicKey) {
        self.add_acount_if_absent(winner);
        let balance = self.map.get_mut(winner).unwrap();
        *balance -= BLOCK_REWARD;
    }
}

fn is_winner(ledger: &Ledger, block: &Block, wallet: &RsaPublicKey) -> bool {
    #[cfg(feature = "always_win")]
    return true;

    let balance = BigUint::from(ledger.get_balance(&wallet));
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
    block.draw.value.clone() * mult_factor > hardness * total_money * max_hash.clone()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Blockchain {
    blocks: Vec<HashMap<[u8; 32], Block>>, // at index i all blocks at depth i exists in a map from their hash to the block
    best_path_head: ([u8; 32], u64), // the hash and depth of the head of the current best path
    ledger: Ledger,                  // this should follow the best_path_heads state
    root_accounts: Vec<RsaPublicKey>,
    orphans: HashMap<[u8; 32], Vec<Block>>, // maps from the parent that they have which is not in blocks
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

        while depth >= self.blocks.len() {
            // create empty hashmaps if the block is in the future, this will usually just be done once
            self.blocks.push(HashMap::new());
            dbg!("updated length to {}", self.blocks.len());
        }

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
                self.ledger
                    .reward_winner(block.draw.signed_by.as_ref(), BLOCK_REWARD);
            }
        } else if depth == self.best_path_head.1 as usize {
            println!("equal depth");
            let new_block = &block;
            let curr_best_block = {
                let (h, d) = &self.best_path_head;
                self.blocks[*d as usize].get(h).unwrap()
            };

            if new_block.is_better_than(curr_best_block) {
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
                    self.ledger.rollback_reward(to_ptr.draw.signed_by.as_ref());
                    for t in from_ptr.transactions.iter() {
                        self.ledger.rollback_transaction(t);
                    }
                    break; // we have reached the genesis block
                }
            }
            let (to_parent_hash, to_parent_depth) = (&to_ptr.prev_hash, to_ptr.depth - 1);
            let old_to_ptr_depth = to_ptr.depth;
            to_ptr = get_block(to_parent_hash, to_parent_depth);

            if old_to_ptr_depth == from_ptr.depth {
                // to_depth is always >= from_depth so we have to ensure that to goes back first
                // we roll back the transactions on the from path
                self.ledger.rollback_reward(to_ptr.draw.signed_by.as_ref());
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
            self.ledger
                .reward_winner(block.draw.signed_by.as_ref(), BLOCK_REWARD);
        }
    }

    /// Simply checks if you've won
    pub fn stake(&self, block: &Block, wallet: &RsaPublicKey) -> bool {
        is_winner(&self.ledger, block, wallet)
    }

    fn proccess_transactions(&mut self, transactions: &Vec<Transaction>) {
        for t in transactions.iter() {
            self.ledger.process_transaction(t); // an optimization is not verifying the transaction here
        }
    }

    /// Verifies that the entire blockchain follows the rules
    pub fn verify_chain(&self) -> bool {
        if !self.check_best_path() {
            println!("not best path");
            return false;
        }

        // there must be exactly 1 genesis block
        let genesis_block = {
            let mut blocks = self.blocks[0].values();
            if blocks.len() == 1 {
                (blocks.next().unwrap().hash, 0)
            } else {
                return false;
            }
        };

        let get_parent_ptr = |ptr: &([u8; 32], u64)| {
            (
                self.blocks[ptr.1 as usize]
                    .get(&ptr.0)
                    .map(|b| b.prev_hash)
                    .unwrap(),
                ptr.1 - 1,
            )
        };

        let get_block = |ptr: &([u8; 32], u64)| self.blocks[ptr.1 as usize].get(&ptr.0).unwrap();

        // we walk from the head, to the genesis block to get a verifiable path
        let mut track_stack = Vec::new();
        let mut walking_ptr = self.best_path_head;
        while walking_ptr != genesis_block {
            track_stack.push(walking_ptr);
            walking_ptr = get_parent_ptr(&walking_ptr);
        }
        // now the track_stack contains all on the best path except genesis
        // we will also track a ledger to see if it matches the proposed ledger
        // we then check the track_stack
        let mut track_ledger = {
            let mut l = Ledger::new();
            self.root_accounts
                .iter()
                .for_each(|acc| l.reward_winner(acc, ROOT_AMOUNT));
            l
        };
        let previous_transactions = HashSet::new();
        let mut prev_ptr = genesis_block;
        let genesis_block = get_block(&genesis_block);
        let mut prev_ts = genesis_block.timeslot;
        while let Some((block_hash, depth)) = track_stack.pop() {
            let block = get_block(&(block_hash, depth));
            if block.timeslot <= prev_ts {
                return false;
            }
            prev_ts = block.timeslot;

            if block.prev_hash != prev_ptr.0 {
                println!("hash mishmatch");
                return false;
            }
            if !block.verify_all(&previous_transactions) {
                println!("block not verified");
                return false;
            }

            // we process the transactions for the track ledger and they must all be valid
            if !block
                .transactions
                .iter()
                .all(|t| track_ledger.process_transaction(&t))
            {
                return false;
            };

            let winner = block.draw.signed_by.as_ref();
            if !is_winner(&track_ledger, block, winner) {
                println!("false winner");
                return false;
            }

            track_ledger.reward_winner(winner, BLOCK_REWARD);

            prev_ptr = (block_hash, depth);
        }

        // we then check the genesis block
        if !genesis_block.transactions.is_empty()
            || !genesis_block.verify_genesis(&self.root_accounts)
        {
            return false;
        }

        if self.ledger != track_ledger {
            dbg!("ledger mismatch {:#?}\n{:#?}", &self.ledger, track_ledger);
            return false;
        }

        true
    }

    /// checks that the best_path head is the correct one
    pub fn check_best_path(&self) -> bool {
        let max_depth = self.best_path_head.1 as usize;
        if self.blocks.len() - 1 != max_depth {
            println!(
                "blocks len does not match depth {} vs {}",
                self.blocks.len() - 1,
                max_depth
            );
            return false;
        }
        let blocks_at_max_depth = self.blocks[max_depth].clone();
        if blocks_at_max_depth.is_empty() {
            println!("no blocks at max depth");
            return false;
        }
        if blocks_at_max_depth.len() > 1 {
            // check for tiebreak between all the blocks
            let mut blocks = blocks_at_max_depth.values().collect::<Vec<_>>();
            let mut greatest_block_so_far = blocks.pop().unwrap();
            for block in blocks {
                if !greatest_block_so_far.is_better_than(block) {
                    greatest_block_so_far = block;
                }
            }

            if (greatest_block_so_far.hash, greatest_block_so_far.depth) != self.best_path_head {
                return false;
            }
        }

        true
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
        let transaction = Transaction::new(from.clone(), to.clone(), &sk, amount, 0);
        let transactions = vec![transaction];

        // Create a block
        let block = Block::new(0, [0; 32], 0, vk.clone(), transactions.clone(), &sk);

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
        ledger.reward_winner(from.as_ref(), 102);
        assert!(ledger.process_transaction(&transaction));

        assert_eq!(ledger.get_balance(&from_rsa), 51);
        assert_eq!(ledger.get_balance(&to_rsa), 50);

        let transaction = Transaction::new(from.clone(), to.clone(), &sk, 50, 1);
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

        let transaction = Transaction::new(vk3.clone(), from.clone(), &sk, 50, 2);

        assert!(!ledger.process_transaction(&transaction)); // invalid signature
    }

    #[cfg(feature = "always_win")]
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

        assert!(blockchain.verify_chain());

        let transaction_b1_1 = Transaction::new(vk1.clone(), vk3.clone(), &sk1, 10, 0);
        let transaction_b1_2 = Transaction::new(vk1.clone(), vk3.clone(), &sk1, 10, 1);

        let transaction_b2_1 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 0);

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
        let transaction_b2_3 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 2);
        let block_b2_3 = Block::new(
            3,
            block_b2_2.hash,
            3,
            vk2.clone(),
            vec![transaction_b2_3],
            &sk2,
        );
        blockchain.add_block(block_b2_2);

        assert!(blockchain.verify_chain());

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

        assert!(blockchain.verify_chain());
    }

    #[cfg(feature = "heavy_test")]
    #[test]
    fn test_stake() {
        // this tests that staking works well
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();

        for i in (1..=30).rev() {
            let (sk, vk) = generate_keypair();
            let mut blockchain = Blockchain::start(
                vec![
                    vk.clone().into(),
                    vk1.clone().into(),
                    vk2.clone().into(),
                    vk3.clone().into(),
                ],
                &sk,
            );
            let mut block = Block::new(
                0,
                blockchain.best_path_head.0,
                1,
                vk.clone().into(),
                Vec::new(),
                &sk,
            );
            let mut tries_vec = Vec::new();
            print!("{i} tries: ");
            for _ in 0..10 {
                block.increment_timeslot();
                block.set_draw(&sk);

                *blockchain.ledger.map.get_mut(&vk.clone().into()).unwrap() = 10 * i;
                let mut has_won = blockchain.stake(&block, &vk.clone().into());
                let mut tries = 0;
                while !has_won {
                    block.increment_timeslot();
                    block.set_draw(&sk);
                    has_won = blockchain.stake(&block, &vk.clone().into());
                    tries += 1;
                }

                print!("{} ", tries);
                tries_vec.push(tries);
            }
            println!(
                " Mean: {}",
                tries_vec.iter().sum::<i64>() as f64 / (tries_vec.len() as f64)
            );
            block.sign_and_rehash(&sk);
            assert!(blockchain.add_block(block));
        }
    }

    #[cfg(feature = "always_win")]
    #[test]
    fn test_orphanage() {
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

        let transaction_b1_1 = Transaction::new(vk1.clone(), vk3.clone(), &sk1, 10, 0);

        let transaction_b2_1 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 0);
        let transaction_b2_2 = Transaction::new(vk1.clone(), vk4.clone(), &sk1, 20, 1);

        let block_b1_1 = Block::new(
            1,
            blockchain.best_path_head.0,
            1,
            vk2.clone(),
            vec![transaction_b1_1],
            &sk2,
        );

        let block_b2_1 = Block::new(
            1,
            blockchain.best_path_head.0,
            1,
            vk2.clone(),
            vec![transaction_b2_1],
            &sk2,
        );

        // this will be added first so it is an orphan
        let block_b2_2 = Block::new(
            2,
            block_b2_1.hash,
            2,
            vk2.clone(),
            vec![transaction_b2_2],
            &sk2,
        );

        assert!(blockchain.verify_chain());

        assert!(blockchain.add_block(block_b1_1));
        assert!(blockchain.orphans.is_empty());

        assert!(blockchain.verify_chain());

        assert!(!blockchain.add_block(block_b2_2));
        assert_eq!(blockchain.orphans.len(), 1);

        assert!(blockchain.verify_chain());

        assert!(blockchain.add_block(block_b2_1));
        assert!(blockchain.orphans.is_empty());
        assert_eq!(
            blockchain.ledger.get_balance(&vk1.clone().into()),
            ROOT_AMOUNT - 40 - 2 * TRANSACTION_FEE
        );
        assert!(blockchain.verify_chain());
    }

    #[test]
    fn test_illegal_genesis_block() {
        let (sk1, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        let (_, vk4) = generate_keypair();

        let mut blockchain = Blockchain::start(
            vec![
                vk1.clone().into(),
                vk2.clone().into(),
                vk3.clone().into(),
                vk4.clone().into(),
            ],
            &sk1,
        );

        assert!(blockchain.verify_chain());

        let zero_map = blockchain.blocks.get_mut(0).unwrap();
        assert_eq!(zero_map.len(), 1);
        let genesis_block = zero_map.get_mut(&blockchain.best_path_head.0).unwrap();
        genesis_block.depth = 1;

        assert!(!blockchain.verify_chain());
    }

    #[test]
    fn test_illegal_transaction() {
        let (sk1, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        let (_, vk4) = generate_keypair();

        let mut blockchain = Blockchain::start(
            vec![
                vk1.clone().into(),
                vk2.clone().into(),
                vk3.clone().into(),
                vk4.clone().into(),
            ],
            &sk1,
        );

        assert!(blockchain.verify_chain());

        let zero_map = blockchain.blocks.get_mut(0).unwrap();
        assert_eq!(zero_map.len(), 1);
        let genesis_block = zero_map.get_mut(&blockchain.best_path_head.0).unwrap();
        genesis_block.transactions = vec![Transaction::new(vk1.clone(), vk1, &sk1, 4, 0)];
        assert!(!blockchain.verify_chain());
    }

    #[cfg(feature = "always_win")]
    #[test]
    fn test_illegal_ledger() {
        let (sk1, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        let (_, vk4) = generate_keypair();

        let mut blockchain = Blockchain::start(vec![
            vk1.clone().into(),
            vk2.clone().into(),
            vk3.clone().into(),
            vk4.clone().into(),
        ], &sk1);

        let mut block = Block::new(1, blockchain.best_path_head.0, 1, vk1.clone(), Vec::new(), &sk1);
        loop {
            if blockchain.stake(&block, vk1.as_ref()) {
                break;
            } else { 
                block.increment_timeslot();
            }
        }

        assert!(blockchain.add_block(block));
    
        assert!(blockchain.verify_chain());
        blockchain.ledger.reward_winner(vk1.as_ref(), 50);
        assert!(!blockchain.verify_chain());
    }

    #[cfg(not(feature = "always_win"))]
    #[test]
    fn test_illegal_block() {
        let (sk1, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let (_, vk3) = generate_keypair();
        let (_, vk4) = generate_keypair();

        let mut blockchain = Blockchain::start(vec![
            vk1.clone().into(),
            vk2.clone().into(),
            vk3.clone().into(),
            vk4.clone().into(),
        ], &sk1);

        let mut block = Block::new(1, blockchain.best_path_head.0, 1, vk1.clone(), Vec::new(), &sk1);
        loop {
            if blockchain.stake(&block, vk1.as_ref()) {
                block.increment_timeslot();
            } else { 
                break;
            }
        }

        assert!(blockchain.verify_chain());
        blockchain.add_block(block);
        assert!(!blockchain.verify_chain());
    }
}
