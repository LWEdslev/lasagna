use std::collections::{HashMap, HashSet};

use rsa::RsaPrivateKey;
use rsa::{pss::SigningKey, sha2::Sha256, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::Timeslot;
use crate::{
    block::Block, is_winner, ledger::Ledger, transaction::Transaction, BLOCK_REWARD, ROOT_AMOUNT,
};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::Digest;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub(super) blocks: Vec<HashMap<[u8; 32], Block>>, // at index i all blocks at depth i exists in a map from their hash to the block
    pub(super) best_path_head: ([u8; 32], u64), // the hash and depth of the head of the current best path
    pub(super) ledger: Ledger,                  // this should follow the best_path_heads state
    pub(super) root_accounts: Vec<RsaPublicKey>,
    pub(super) orphans: HashMap<[u8; 32], Vec<Block>>, // maps from the parent that they have which is not in blocks
    pub(super) transaction_buffer: Vec<Transaction>, // TODO(before pre-alpha) this should be a HashMap<Timeslot, Vec<Transaction>>
    start_time: u128,
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
            start_time: crate::get_unix_timestamp(),
        }
    }

    /// Returns whether the new block extends the best path
    pub fn add_block(&mut self, block: Block) -> bool {
        if !block.verify_signature() {
            println!("signature invalid");
            return false;
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
                &hex::encode(self.best_path_head.0)[0..5]
            );
            return false;
        };

        // we check the timeslot
        if block.timeslot <= parent_block.timeslot || block.timeslot > self.calculate_timeslot(){
            println!("signature timeslot mismatch");
            dbg!(block.timeslot);
            dbg!(parent_block.timeslot);
            dbg!(self.calculate_timeslot());
            return false;
        }

        while depth >= self.blocks.len() {
            // create empty hashmaps if the block is in the future, this will usually just be done once
            self.blocks.push(HashMap::new());
            //dbg!("updated length to {}", self.blocks.len());
        }

        // clone the stuff we need later
        let block_hash = block.hash.clone();
        // we add ourself
        self.blocks
            .get_mut(depth)
            .expect("unreachable")
            .insert(block.hash.clone(), block.clone());

        // remove all transactions from the buffer that are in the block
        self.transaction_buffer.retain(|t| !block.transactions.contains(t));

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
            //println!("equal depth");
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

    pub fn get_latest_block(&self) -> &Block {
        self.blocks[self.best_path_head.1 as usize]
            .get(&self.best_path_head.0)
            .unwrap()
    }

    fn calculate_timeslot(&self) -> Timeslot {
        #[cfg(feature = "max_timeslot")]
        return u64::MAX;

        let now = crate::get_unix_timestamp();
        let start = self.start_time;
        let timeslot = (now - start) / 10;
        timeslot as _
    }

    pub fn create_empty_mining_block(
        &self,
        account: RsaPublicKey,
        account_sk: &RsaPrivateKey,
    ) -> Block {
        Block::new(
            self.calculate_timeslot(),
            self.best_path_head.0,
            self.best_path_head.1 + 1,
            account.into(),
            Vec::new(),
            &account_sk.clone().into(),
        )
    }

    pub fn create_mining_block(
        &self,
        account: RsaPublicKey,
        account_sk: &RsaPrivateKey,
    ) -> Block {
        Block::new(
            self.calculate_timeslot(),
            self.best_path_head.0,
            self.best_path_head.1 + 1,
            account.into(),
            self.transaction_buffer.clone(),
            &account_sk.clone().into(),
        )
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> bool {
        if transaction.verify_signature()
            && self.ledger.is_transaction_possible(&transaction)
        {
            self.transaction_buffer.push(transaction);
            println!("transaction added to buffer");
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
            if to_ptr.depth == 1 && from_ptr.depth == 1 {
                if to_ptr.prev_hash == from_ptr.prev_hash {
                    self.ledger.rollback_reward(to_ptr.draw.signed_by.as_ref());
                    for t in from_ptr.transactions.iter() {
                        self.ledger.rollback_transaction(t);
                        self.transaction_buffer.push(t.clone()); // we have to readd the transactions to the buffer
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

    pub fn get_balance(&self, account_sk: &RsaPublicKey) -> u64 {
        self.ledger.map.get(account_sk).cloned().unwrap_or(0)
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

    pub fn get_best_hash(&self) -> [u8; 32] {
        self.best_path_head.0
    }
    
    pub(crate) fn update_mining_block(&self, mining_block: &mut Block) {
        let (best_hash, best_depth) = self.best_path_head;
        mining_block.depth = best_depth + 1;
        mining_block.prev_hash = best_hash;
        mining_block.transactions = self.transaction_buffer.clone();
    }
    
    pub(crate) fn update_mining_block_timeslot(&self, mining_block: &mut Block) {
        mining_block.timeslot = self.calculate_timeslot();
    }
}
