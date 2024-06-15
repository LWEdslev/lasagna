use std::collections::{HashMap, HashSet};

use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::{transaction::Transaction, BLOCK_REWARD, TRANSACTION_FEE};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ledger {
    pub(super) map: HashMap<RsaPublicKey, u64>,
    pub(super) previous_transactions: HashSet<[u8; 32]>,
    pub(super) published_accounts: HashMap<RsaPublicKey, u64>, // maps to depth of publish
}

impl Ledger {
    pub fn new(root_accounts: Vec<RsaPublicKey>) -> Self {
        let mut published_accounts = HashMap::new();
        for acc in root_accounts {
            published_accounts.insert(acc, 0);
        }

        Self {
            map: HashMap::new(),
            previous_transactions: HashSet::new(),
            published_accounts,
        }
    }

    pub fn add_acount_if_absent(&mut self, account: &RsaPublicKey) {
        if !self.map.contains_key(account) {
            self.map.insert(account.clone(), 0);
        }
    }

    pub fn get_balance(&self, account: &RsaPublicKey) -> u64 {
        *self.map.get(account).unwrap_or(&0)
    }

    pub fn reward_winner(&mut self, winner: &RsaPublicKey, amount: u64) {
        self.add_acount_if_absent(winner);
        let balance = self.map.get_mut(winner).unwrap();
        *balance += amount;
    }

    /// Panics if the transaction has been added previously
    /// depth is the depth of the block where this happens
    pub fn process_transaction(&mut self, transaction: &Transaction, depth: u64) -> bool {
        if !transaction.verify_signature() {
            return false;
        };
        if transaction.amount < TRANSACTION_FEE {
            return false;
        };
        let from: &RsaPublicKey = &transaction.from;
        let to: &RsaPublicKey = &transaction.to;
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

        if amount < 1 {
            return false; 
        }

        *from_balance -= amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(to).unwrap();

        *to_balance += amount;

        // check if this is an account publication
        if self.published_accounts.contains_key(to) {
            self.published_accounts.insert(to.clone(), depth);
        }

        true
    }

    /// Reverse the transaction
    /// panics if the transaction was not performed
    pub fn rollback_transaction(&mut self, transaction: &Transaction, depth: u64) {
        let from: &RsaPublicKey = &transaction.from;
        let to: &RsaPublicKey = &transaction.to;
        let amount = transaction.amount;

        assert!(self.previous_transactions.remove(&transaction.hash));

        let from_balance = self.map.get_mut(from).unwrap();

        *from_balance += amount + TRANSACTION_FEE;
        let to_balance = self.map.get_mut(to).unwrap();
        *to_balance -= amount;

        // check if this transaction is an account publication
        // if it is we remove it from the publications
        if let Some(published_at) = self.published_accounts.get(to) {
            let published_at = *published_at;
            if published_at == depth {
                self.published_accounts.remove(to);
            }
        }
    }

    /// TODO maintain this in a variable instead
    pub fn get_total_money_in_ledger(&self) -> u64 {
        self.map.values().sum()
    }

    pub(super) fn rollback_reward(&mut self, winner: &RsaPublicKey) {
        self.add_acount_if_absent(winner);
        let balance = self.map.get_mut(winner).unwrap();
        *balance -= BLOCK_REWARD;
    }
    
    pub(crate) fn is_transaction_possible(&self, transaction: &Transaction) -> bool {
        if !transaction.verify_signature() {
            return false;
        };
        if transaction.amount < TRANSACTION_FEE {
            return false;
        };
        let from: &RsaPublicKey = &transaction.from;
        let amount = transaction.amount;

        let Some(from_balance) = self.map.get(from) else {
            return false; // if the account does not exist it can't have enough money to pay the fee
        };

        if *from_balance < amount + TRANSACTION_FEE {
            return false;
        }

        if self.previous_transactions.contains(&transaction.hash) {
            return false; // if we have already proccessed this
        }

        true
    }
}