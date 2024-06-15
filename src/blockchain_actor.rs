use std::fmt::Debug;

use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::sync::{
    mpsc::Sender,
    oneshot,
};

use crate::{
    block::Block, blockchain::Blockchain, clock_watch::ClockWatch, transaction::Transaction, ClientMessage
};

struct BlockchainActor {
    sending_channel: tokio::sync::mpsc::Sender<ClientMessage>,
    blockchain: Blockchain,
    account: RsaPublicKey,
    account_sk: RsaPrivateKey,
}

impl BlockchainActor {
    fn run(
        blockchain: Blockchain,
        account: RsaPublicKey,
        account_sk: RsaPrivateKey,
        sending_channel: tokio::sync::mpsc::Sender<ClientMessage>,
    ) -> Self {
        Self {
            sending_channel,
            blockchain,
            account,
            account_sk,
        }
    }

    async fn handle_message(&mut self, msg: BlockchainActorMessage) {
        use BlockchainActorMessage::*;
        match msg {
            AddTransaction(t) => {
                self.blockchain.add_transaction(t.clone());
            }
            AddBlock(b) => {
                if let Err(e) = self.blockchain.add_block(b) {
                    println!("Error when adding block: {:?}", e)
                }
            }
            CheckBalance(pk) => {
                let balance = self.blockchain.get_balance(&pk);
                self.sending_channel
                    .send(ClientMessage::BalanceOf(pk, balance))
                    .await
                    .unwrap();
            }
            Stake => {
                let draw = self.blockchain.get_draw(&self.account_sk);
                let prev_hash = self.blockchain.get_best_hash();
                let new_depth = self.blockchain.best_path_head().1 + 1;
                if self.blockchain.stake(draw.clone(), &self.account, new_depth) {
                    let block = self
                        .blockchain
                        .get_new_block(prev_hash, draw.clone(), &self.account_sk);
                    match self.blockchain.add_block(block.clone()) {
                        Ok(_) => {
                            self.sending_channel
                            .send(ClientMessage::Won(block.clone()))
                            .await
                            .unwrap();
                        },
                        Err(e) => println!("Error when adding block: {:?}", e),
                    } 
                } else {
                    //println!("lost a stake whomp whomp");
                }
            }
            BlockchainCopy(callback) => {
                callback.send(self.blockchain.clone()).unwrap();
            }
            GetStartTime(callback) => {
                callback.send(self.blockchain.get_start_time()).unwrap();
            }
        }
    }
}

enum BlockchainActorMessage {
    AddTransaction(Transaction),
    AddBlock(Block),
    CheckBalance(RsaPublicKey),
    Stake,
    BlockchainCopy(oneshot::Sender<Blockchain>),
    GetStartTime(oneshot::Sender<u128>),
}

impl Debug for BlockchainActorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BlockchainActorMessage::*;
        match self {
            AddTransaction(_) => write!(f, "AddTransaction"),
            AddBlock(_) => write!(f, "AddBlock"),
            CheckBalance(_) => write!(f, "CheckBalance"),
            Stake => write!(f, "Stake"),
            BlockchainCopy(_) => write!(f, "BlockchainCopy"),
            GetStartTime(_) => write!(f, "GetStartTime"),
        }
    }
}

#[derive(Clone)]
pub struct BlockchainActorHandle {
    sender: tokio::sync::mpsc::Sender<BlockchainActorMessage>,
}

impl BlockchainActorHandle {
    pub async fn new(
        blockchain: Blockchain,
        account: RsaPublicKey,
        account_sk: RsaPrivateKey,
        client_tx: Sender<ClientMessage>,
    ) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
        let start_time = blockchain.get_start_time();

        let mut actor = BlockchainActor::run(blockchain, account, account_sk, client_tx.clone());
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                actor.handle_message(msg).await
            }
        });

        // start a task that sends stake messages at beginning of timeslot, to keep checking if we won
        {
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut clock = ClockWatch::start(start_time);
                loop {
                    clock.wait_for_update().await;
                    sender.send(BlockchainActorMessage::Stake).await.unwrap();
                }
            });
        }

        Self { sender }
    }

    pub async fn add_transaction(&self, transaction: Transaction) {
        self.sender
            .send(BlockchainActorMessage::AddTransaction(transaction))
            .await
            .unwrap();
    }

    pub async fn add_block(&self, block: Block) {
        self.sender
            .send(BlockchainActorMessage::AddBlock(block))
            .await
            .unwrap();
    }

    pub async fn check_balance(&self, account: RsaPublicKey) {
        self.sender
            .send(BlockchainActorMessage::CheckBalance(account))
            .await
            .unwrap();
    }

    pub async fn stake(&self) {
        self.sender
            .send(BlockchainActorMessage::Stake)
            .await
            .unwrap();
    }

    pub async fn get_blockchain_copy(&self) -> Blockchain {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(BlockchainActorMessage::BlockchainCopy(tx))
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub async fn get_start_time(&self) -> u128 {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(BlockchainActorMessage::GetStartTime(tx))
            .await
            .unwrap();
        rx.await.unwrap()
    }
}
