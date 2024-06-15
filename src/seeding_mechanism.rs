use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::block::Block;

/// Purpose of this is to provide the lottery a seed
///   and update this accordingliy

/// Basically we look at a block on the best path
/// When our seed is 100 blocks old, we choose a new seed, 50 blocks old
/// We also need to manage if a rollback occurs further back than this
/// Ideally we would need finality of the block we use for seeding.
///
/// So a block is valid if it's seeds depth is in [50, 100].
/// If it is 100 then the next seed will be the best path but 50 back.
/// If it is less than 100 (but more than 50) we must check that the parent block is the same
/// If it is exactly 50 we must check that 50 back is the correct seed
/// It is only possible to win a block, if the seed's corresponding block
///     contains the winning wallet
/// The genesis block and the proceeding 100 blocks just use some hash of the root accounts 

pub const MAX_SEED_AGE: u64 = 100;
pub const MIN_SEED_AGE: u64 = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedContent {
    pub(crate) block_ptr: ([u8; 32], u64),
    pub(crate) seed: [u8; 32],
}

impl SeedContent {
    pub fn new(block_ptr: ([u8; 32], u64), seed: [u8; 32]) -> Self {
        Self {
            block_ptr,
            seed,
        }
    }

    pub(crate) fn does_seed_correspond_to_block(&self, blocks: &Vec<HashMap<[u8; 32], Block>>) -> bool {
        let block = match blocks
            .get(self.block_ptr.1 as usize)
            .and_then(|map| map.get(&self.block_ptr.0))
        {
            Some(b) => b,
            None => return false,
        };

        if block.depth == 0 {
            return block.prev_hash == block.draw.seed.seed
        };

        block.draw.seed.seed == self.seed
    }

    pub(crate) fn is_seed_in_range(&self, best_depth: u64) -> bool {
        let seed_age = best_depth - self.block_ptr.1;
        if seed_age < MIN_SEED_AGE && best_depth >= MIN_SEED_AGE {
            return false;
        }

        if seed_age > MAX_SEED_AGE {
            return false;
        }

        true
    }
}
