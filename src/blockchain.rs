use std::collections::{HashMap, HashSet};

use rsa::pkcs8::der::zeroize::Zeroizing;
use rsa::RsaPrivateKey;
use rsa::{sha2::Sha256, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::draw::Draw;
use crate::seeding_mechanism::{self, SeedContent, MAX_SEED_AGE, MIN_SEED_AGE};
use crate::Result;
use crate::{
    block::Block, is_winner, ledger::Ledger, transaction::Transaction, BLOCK_REWARD, ROOT_AMOUNT,
};
use crate::{Timeslot, SLOT_LENGTH};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::Digest;

#[derive(Error, Debug, PartialEq)]
pub enum BlockchainError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("No parent was found to the block")]
    OrphanBlock,
    #[error("Invalid timeslot")]
    InvalidTimeslot,
    #[error("Best path not updated")]
    BestPathNotUpdated,
    #[error("Invalid best path")]
    InvalidBestPath,
    #[error("Invalid genesis block")]
    InvalidGenesisBlock,
    #[error("Invalid transaction")]
    InvalidTransaction,
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Unable to verify block")]
    UnableToVerifyBlock,
    #[error("False winner")]
    FalseWinner,
    #[error("Invalid ledger")]
    InvalidLedger,
    #[error("Empty blockchain. There were not blocks")]
    EmptyChain,
    #[error("Invalid seed")]
    InvalidSeed,
}

impl<T> From<BlockchainError> for Result<T> {
    fn from(value: BlockchainError) -> Self {
        Err(crate::Error::BlockchainError(value))
    }
}

impl From<BlockchainError> for crate::Error {
    fn from(value: BlockchainError) -> Self {
        crate::Error::BlockchainError(value)
    }
}

pub type BlockPtr = ([u8; 32], u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub(super) blocks: Vec<HashMap<[u8; 32], Block>>, // at index i all blocks at depth i exists in a map from their hash to the block
    pub(super) best_path: Vec<BlockPtr>,              // best path
    pub(super) ledger: Ledger, // this should follow the best_path_heads state
    pub(super) root_accounts: Vec<RsaPublicKey>,
    pub(super) orphans: HashMap<[u8; 32], Vec<Block>>, // maps from the parent that they have which is not in blocks
    pub(super) transaction_buffer: HashSet<Transaction>,
    start_time: u128,
}

impl Blockchain {
    pub fn get_start_time(&self) -> u128 {
        self.start_time
    }

    fn produce_root_seed(root_accounts: &Vec<RsaPublicKey>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for ra in root_accounts.iter() {
            hasher.update(ra.to_pkcs1_der().unwrap().as_bytes());
        }

        hasher.finalize().into()
    }

    pub fn start(root_accounts: Vec<RsaPublicKey>, any_sk: &RsaPrivateKey) -> Self {
        let seed_hash: [u8; 32] = Self::produce_root_seed(&root_accounts);

        let block = Block::new(
            0,
            seed_hash,
            0,
            root_accounts.first().unwrap().clone(),
            Vec::new(),
            any_sk,
            SeedContent::new((seed_hash, 0), seed_hash),
        );
        let hash = block.hash;
        let mut map = HashMap::new();
        map.insert(hash, block.clone());
        let mut ledger = Ledger::new(root_accounts.clone());
        for root_account in root_accounts.iter() {
            ledger.reward_winner(root_account, ROOT_AMOUNT);
        }

        let blocks = vec![map];

        let _buffer_ledger = ledger.clone();

        Self {
            blocks,
            best_path: vec![(hash, 0)],
            ledger,
            root_accounts,
            orphans: HashMap::new(),
            transaction_buffer: HashSet::new(),
            start_time: crate::get_unix_timestamp(),
        }
    }

    pub fn best_path_head(&self) -> &BlockPtr {
        self.best_path.last().expect("unreachable")
    }

    fn check_seed(&self, block: &Block) -> bool {
        let depth = block.depth as u64;

        let seed_age = || depth as u64 - block.draw.seed.block_ptr.1; // closure to evaluate lazily
                                                                      // check that the seed is ok
        if depth < MAX_SEED_AGE as _ && depth > 0 {
            // if we are close to genesis we must have same seed as genesis block
            if block.draw.seed != self.get_block(&self.best_path[0]).unwrap().draw.seed {
                eprintln!("we do not have the same seed as the genesis block");
                return false;
            }
        } else if seed_age() > MIN_SEED_AGE && seed_age() <= MAX_SEED_AGE {
            // in range, we must check if seed matches previous
            let prev_block = self.get_block(&self.best_path[depth as usize - 1]).unwrap();
            if block.draw.seed != prev_block.draw.seed {
                eprintln!("block does not match previous at depth {}", depth);
                eprintln!(
                    "({},{}){}) seed_age = {}",
                    hex::encode(block.draw.seed.block_ptr.0),
                    block.draw.seed.block_ptr.1,
                    hex::encode(block.draw.seed.seed),
                    seed_age()
                );
                eprintln!(
                    "prev ({},{}){})",
                    hex::encode(prev_block.draw.seed.block_ptr.0),
                    prev_block.draw.seed.block_ptr.1,
                    hex::encode(prev_block.draw.seed.seed)
                );
                return false;
            }
        } else if seed_age() == MIN_SEED_AGE {
            // on lower border, we must check if it is MIN_SEED_AGE back
            // we must check that the hash of the draw MIN_SEED_AGE back is the seed
            let old_block = self
                .get_block(&self.best_path[(depth - (MIN_SEED_AGE)) as usize])
                .unwrap();
            if block.draw.seed
                != SeedContent::new((old_block.hash, old_block.depth), old_block.draw.hash())
            {
                eprintln!("seed does not match MIN_SEED_AGE blocks back");
                eprintln!(
                    "comparing ({}) with ({}) at depth {}",
                    block.draw.seed.block_ptr.1, old_block.depth, block.depth
                );
                return false;
            }
        } else {
            // check genesis
            let genesis_seed = Self::produce_root_seed(&self.root_accounts);
            if !(depth == 0 && block.draw.seed.seed == genesis_seed) {
                eprintln!(
                    "out of range seed {} depth {} genesis_seed {} seed_age {}",
                    hex::encode(block.draw.seed.seed),
                    depth,
                    hex::encode(genesis_seed),
                    seed_age()
                );
                // out of range, this is always invalid (if not genesis)
                return false;
            }
        }

        true
    }

    /// Returns whether the new block extends the best path
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        if !block.verify_signature() {
            println!("signature invalid");
            return BlockchainError::InvalidSignature.into();
        }
        let depth = block.depth as usize;

        let get_parent = |parent_hash: [u8; 32]| {
            let map = self.blocks.get(depth - 1)?;
            map.get(&parent_hash)
        };

        let parent_hash = block.prev_hash;
        let parent_block = get_parent(block.prev_hash);
        let Some(parent_block) = parent_block else {
            // the parent does not exist yet so we are an orphan
            if let Some(orphans_of_prev) = self.orphans.get_mut(&block.prev_hash) {
                orphans_of_prev.push(block);
            } else {
                self.orphans.insert(block.prev_hash, vec![block]);
            }
            println!(
                "unable to find parent block, was looking for {:?}, best path head is {}",
                &hex::encode(parent_hash)[0..5],
                &hex::encode(self.best_path_head().0)[0..5]
            );
            return BlockchainError::OrphanBlock.into();
        };

        // we check the timeslot
        if block.timeslot <= parent_block.timeslot || block.timeslot > self.calculate_timeslot() {
            println!("signature timeslot mismatch");
            dbg!(block.timeslot);
            dbg!(parent_block.timeslot);
            dbg!(self.calculate_timeslot());
            return BlockchainError::InvalidTimeslot.into();
        }

        // check the seed
        if !self.check_seed(&block) {
            return BlockchainError::InvalidSeed.into();
        }

        while depth >= self.blocks.len() {
            // create empty hashmaps if the block is in the future, this will usually just be done once
            self.blocks.push(HashMap::new());
        }

        // clone the stuff we need later
        let block_hash = block.hash;
        // we add ourself
        self.blocks
            .get_mut(depth)
            .expect("unreachable")
            .insert(block.hash, block.clone());

        // remove all transactions from the buffer that are in the block
        for t in block.transactions.iter() {
            self.transaction_buffer.remove(t);
        }

        // we check if this is the new best path
        let (old_best_path, old_depth) = *self.best_path_head();

        if depth > old_depth as _ {
            // this is definetely the new best path
            //self.best_path_head = (block_hash, depth as _);

            // rollback if we changed branch
            if old_best_path != parent_hash {
                println!("rollback 1");
                self.rollback((old_best_path, old_depth), (block_hash, depth as _));
            } else {
                self.proccess_transactions(&block.transactions, block.depth);
                self.ledger
                    .reward_winner(&block.draw.signed_by, BLOCK_REWARD);
                self.best_path.push((block.hash, block.depth));
            }
        } else if depth == old_depth as usize {
            //println!("equal depth");
            let new_block = &block;
            let curr_best_block = self.blocks[old_depth as usize].get(&old_best_path).unwrap();

            if new_block.is_better_than(curr_best_block) {
                //self.best_path_head = (block_hash, depth as _);
                // we always have to rollback in this case
                println!("rollback 2");
                self.rollback((old_best_path, old_depth), (block_hash, depth as _));
            }
        }

        // we check if we have any orphans, if we do we must add them after ourself
        if let Some(orphans) = self.orphans.remove(&block_hash) {
            for orphan in orphans {
                println!(
                    "Added orphan, result = {:?}",
                    self.add_block(orphan.clone())
                );
            }
        }

        // return whether the best_path has been updated
        (old_best_path != self.best_path_head().0)
            .then_some(())
            .ok_or(crate::Error::BlockchainError(
                BlockchainError::BestPathNotUpdated,
            ))
    }

    fn calculate_timeslot(&self) -> Timeslot {
        #[cfg(feature = "max_timeslot")]
        return u64::MAX;

        let now = crate::get_unix_timestamp();
        let start = self.start_time;
        let timeslot = (now - start) / SLOT_LENGTH;
        timeslot as _
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> bool {
        if transaction.verify_signature() && self.ledger.is_transaction_possible(&transaction) {
            self.transaction_buffer.insert(transaction);
            true
        } else {
            println!("invalid transaction");
            false
        }
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
            let popped = self.best_path.pop().unwrap();
            assert_eq!(popped, (to_ptr.hash, to_ptr.depth));

            if to_ptr.depth == 1 && from_ptr.depth == 1 && to_ptr.prev_hash == from_ptr.prev_hash {
                self.ledger.rollback_reward(&to_ptr.draw.signed_by);
                for t in from_ptr.transactions.iter() {
                    self.ledger.rollback_transaction(t, from_ptr.depth);
                    self.transaction_buffer.insert(t.clone()); // we have to readd the transactions to the buffer
                }
                break; // we have reached the genesis block
            }
            let (to_parent_hash, to_parent_depth) = (&to_ptr.prev_hash, to_ptr.depth - 1);
            let old_to_ptr_depth = to_ptr.depth;

            to_ptr = get_block(to_parent_hash, to_parent_depth);

            if old_to_ptr_depth == from_ptr.depth {
                // to_depth is always >= from_depth so we have to ensure that to goes back first
                // we roll back the transactions on the from path
                self.ledger.rollback_reward(&to_ptr.draw.signed_by);
                for t in from_ptr.transactions.iter() {
                    self.ledger.rollback_transaction(t, from_ptr.depth);
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
                self.ledger.process_transaction(t, block.depth);
            }
            self.ledger
                .reward_winner(&block.draw.signed_by, BLOCK_REWARD);
            self.best_path.push((hash, depth));
        }
    }

    /// Simply checks if you've won
    pub fn stake(&self, draw: Draw, wallet: &RsaPublicKey, depth: u64) -> bool {
        is_winner(&self.ledger, draw, wallet, depth)
    }

    fn proccess_transactions(&mut self, transactions: &Vec<Transaction>, depth: u64) {
        for t in transactions.iter() {
            self.ledger.process_transaction(t, depth);
        }
    }

    pub fn get_balance(&self, account_sk: &RsaPublicKey) -> u64 {
        self.ledger.map.get(account_sk).cloned().unwrap_or(0)
    }

    fn verify_seeds(&self) -> Result<()> {
        for ptr in self.best_path.iter() {
            let block = self
                .get_block(ptr)
                .ok_or::<crate::Error>(BlockchainError::InvalidSeed.into())?;
            if !self.check_seed(block) {
                return BlockchainError::InvalidSeed.into();
            }
        }

        Ok(())
    }

    /// Verifies that the entire blockchain follows the rules
    pub fn verify_chain(&self) -> Result<()> {
        if !self.check_best_path() {
            println!("not best path");
            return BlockchainError::InvalidBestPath.into();
        }

        // there must be exactly 1 genesis block
        let genesis_block = {
            let mut blocks = self.blocks[0].values();
            if blocks.len() == 1 {
                (blocks.next().unwrap().hash, 0)
            } else {
                return BlockchainError::InvalidGenesisBlock.into();
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
        let mut walking_ptr = *self.best_path_head();
        while walking_ptr != genesis_block {
            track_stack.push(walking_ptr);
            walking_ptr = get_parent_ptr(&walking_ptr);
        }
        // now the track_stack contains all on the best path except genesis
        // we will also track a ledger to see if it matches the proposed ledger
        // we then check the track_stack
        let mut track_ledger = {
            let mut l = Ledger::new(self.root_accounts.clone());
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
                return BlockchainError::InvalidTimeslot.into();
            }
            prev_ts = block.timeslot;

            if block.prev_hash != prev_ptr.0 {
                println!("hash mishmatch");
                return BlockchainError::HashMismatch.into();
            }
            if !block.verify_all(&previous_transactions) {
                println!("block not verified");
                return BlockchainError::UnableToVerifyBlock.into();
            }

            let winner = &block.draw.signed_by;
            if !is_winner(&track_ledger, block.draw.clone(), winner, block.depth) {
                println!("false winner");
                return BlockchainError::FalseWinner.into();
            }

            // we process the transactions for the track ledger and they must all be valid
            if !block
                .transactions
                .iter()
                .all(|t| track_ledger.process_transaction(t, block.depth))
            {
                return BlockchainError::InvalidTransaction.into();
            };

            track_ledger.reward_winner(winner, BLOCK_REWARD);

            prev_ptr = (block_hash, depth);
        }

        // we then check the genesis block
        if !genesis_block.transactions.is_empty()
            || !genesis_block.verify_genesis(&self.root_accounts)
        {
            return BlockchainError::InvalidGenesisBlock.into();
        }

        if self.ledger != track_ledger {
            dbg!("ledger mismatch {:#?}\n{:#?}", &self.ledger, track_ledger);
            return BlockchainError::InvalidLedger.into();
        }

        Ok(())
    }

    /// checks that the best_path head is the correct one
    pub fn check_best_path(&self) -> bool {
        let max_depth = self.best_path_head().1 as usize;
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

            if &(greatest_block_so_far.hash, greatest_block_so_far.depth) != self.best_path_head() {
                return false;
            }
        }

        true
    }

    pub fn get_best_hash(&self) -> [u8; 32] {
        self.best_path_head().0
    }

    fn get_best_block(&self) -> &Block {
        self.get_block(self.best_path_head()).expect("unreachable")
    }

    fn get_block(&self, ptr: &BlockPtr) -> Option<&Block> {
        self.blocks
            .get(ptr.1 as usize)
            .and_then(|map| map.get(&ptr.0))
    }

    fn get_parent(&self, block: &Block) -> Option<&Block> {
        if block.depth == 0 {
            return None;
        };
        let block_ptr = (block.prev_hash, block.depth - 1);
        self.get_block(&block_ptr)
    }

    fn get_next_seed(&self) -> SeedContent {
        let best_block = self.get_best_block();
        let seed_content = best_block.draw.seed.clone();

        let seed_age = best_block.depth - seed_content.block_ptr.1;
        if (seed_age >= MIN_SEED_AGE && seed_age < MAX_SEED_AGE) || best_block.depth < MIN_SEED_AGE
        {
            // use previous seed
            return seed_content;
        }

        // seed >= 100 so we pick a new seed
        // we do this by walking 50 back from our best block
        let block = self
            .get_block(&self.best_path[(best_block.depth - MIN_SEED_AGE + 1) as usize])
            .unwrap();

        SeedContent {
            block_ptr: (block.hash, block.depth),
            seed: block.draw.hash(),
        }
    }

    pub fn get_draw(&self, sk: &RsaPrivateKey) -> Draw {
        Draw::new(
            self.calculate_timeslot(),
            self.get_next_seed(),
            sk.to_public_key(),
            sk,
        )
    }

    pub(crate) fn get_new_block(
        &self,
        prev_hash: [u8; 32],
        draw: Draw,
        sk: &RsaPrivateKey,
    ) -> Block {
        let mut checking_ledger = self.ledger.clone();
        let new_depth = self.best_path_head().1 + 1;
        let mut transactions_buffer: Vec<_> = self.transaction_buffer.clone().into_iter().collect();
        // this could cause many transactions in the same block depth to only get a few valid in random order
        transactions_buffer.retain(|t| checking_ledger.process_transaction(t, new_depth));

        Block::new(
            draw.timeslot,
            prev_hash,
            new_depth,
            draw.signed_by.clone(),
            transactions_buffer,
            sk,
            draw.seed,
        )
    }
}

#[cfg(test)]
impl Blockchain {
    // Keeps mining until winning, since this is a test it will be fast
    // A timeslot is only 0.001 ms when testing
    fn produce_new_block_on_best_path(
        &mut self,
        sk: &RsaPrivateKey,
        max_attempts: u64,
    ) -> Result<()> {
        let wallet = sk.to_public_key();
        let mut attempts = 1;
        let mut draw = self.get_draw(sk);
        while !self.stake(draw.clone(), &wallet, self.best_path_head().1 + 1)
            && attempts < max_attempts
        {
            draw = self.get_draw(sk);
            attempts += 1;
        }

        self.add_block(self.get_new_block(self.get_best_hash(), draw, sk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_blockchain() -> (Blockchain, Vec<RsaPrivateKey>) {
        let k1 = crate::cli::key_from_seedphrase(&Zeroizing::new(
            "abstract gap pumpkin exchange crawl rapid grief glad private people popular harsh"
                .into(),
        ))
        .unwrap();
        let k2 = crate::cli::key_from_seedphrase(&Zeroizing::new(
            "hole fall spin vote bracket relax dolphin trumpet trick elbow wise force".into(),
        ))
        .unwrap();
        let k3 = crate::cli::key_from_seedphrase(&Zeroizing::new(
            "shell peasant gorilla disorder state gate worth narrow afford liar pilot evil".into(),
        ))
        .unwrap();
        let k4 = crate::cli::key_from_seedphrase(&Zeroizing::new(
            "abstract gap pumpkin exchange crawl rapid grief glad private people popular harsh"
                .into(),
        ))
        .unwrap();

        let root_accounts = vec![
            k1.to_public_key(),
            k2.to_public_key(),
            k3.to_public_key(),
            k4.to_public_key(),
        ];

        let blockchain = Blockchain::start(root_accounts, &k1);

        (blockchain, vec![k1, k2, k3, k4])
    }

    #[test]
    fn produce_block() {
        let (mut blockchain, keys) = create_dummy_blockchain();

        let max_attempts = 200;

        assert_eq!(
            blockchain.produce_new_block_on_best_path(&keys[0], max_attempts),
            Ok(())
        );
        assert_eq!(blockchain.verify_chain(), Ok(()));
        assert_eq!(blockchain.verify_seeds(), Ok(()));
    }

    #[test]
    fn produce_max_age_blocks() {
        let (mut blockchain, keys) = create_dummy_blockchain();

        let max_attempts = 1000;

        for i in 0..(MAX_SEED_AGE + 2) {
            eprintln!("iter i {i}");
            assert_eq!(
                blockchain.produce_new_block_on_best_path(&keys[0], max_attempts),
                Ok(())
            );
            assert_eq!(blockchain.verify_chain(), Ok(()));
            assert_eq!(blockchain.verify_seeds(), Ok(()));
        }
    }
}

/*
TESTING SEED PHRASES

abstract gap pumpkin exchange crawl rapid grief glad private people popular harsh
hole fall spin vote bracket relax dolphin trumpet trick elbow wise force
shell peasant gorilla disorder state gate worth narrow afford liar pilot evil
sick column north another embody dog talent barrel story speak pattern tip
extend south trumpet alter unusual used miss approve level outer universe lawn
*/
