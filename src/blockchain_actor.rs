use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{block::Block, blockchain::Blockchain, transaction::Transaction, ClientMessage, Timeslot};

struct BlockchainActor {
    sending_channel: tokio::sync::mpsc::Sender<ClientMessage>,
    blockchain: Blockchain,
    mining_block: Block,
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
        let mining_block = blockchain.create_mining_block(account.clone(), &account_sk);
            Self {
                sending_channel,
                blockchain,
                mining_block,
                account,
                account_sk,
            }
    }

    async fn handle_message(&mut self, msg: BlockchainActorMessage) {
        use BlockchainActorMessage::*;
        match msg {
            AddTransaction(t) => {
                self.blockchain.add_transaction(t);
            }
            AddBlock(b) => {
                self.blockchain.add_block(b);
                self.blockchain.update_mining_block(&mut self.mining_block);
            }
            CheckBalance(pk) => {
                let balance = self.blockchain.get_balance(&pk);
                self.sending_channel
                    .send(ClientMessage::BalanceOf(pk, balance))
                    .await
                    .unwrap();
            }
            Stake => {
                self.blockchain
                    .update_mining_block_timeslot(&mut self.mining_block);
                self.mining_block.set_draw(&self.account_sk.clone().into());
                if self.blockchain.stake(&self.mining_block, &self.account) {
                    self.mining_block
                        .sign_and_rehash(&self.account_sk.clone().into());
                    self.blockchain.add_block(self.mining_block.clone());
                    self.sending_channel
                        .send(ClientMessage::Won(self.mining_block.clone()))
                        .await
                        .unwrap();
                    self.blockchain.update_mining_block(&mut self.mining_block);
                } else {
                    println!("lost a stake whomp whomp");
                }
            }
        }
    }
}

enum BlockchainActorMessage {
    AddTransaction(Transaction),
    AddBlock(Block),
    CheckBalance(RsaPublicKey),
    Stake,
}

#[derive(Clone)]
pub struct BlockchainActorHandle {
    sender: tokio::sync::mpsc::Sender<BlockchainActorMessage>,
}

impl BlockchainActorHandle {
    pub fn new(
        blockchain: Blockchain,
        account: RsaPublicKey,
        account_sk: RsaPrivateKey,
        client_tx: Sender<ClientMessage>,
    ) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
        let mut actor = BlockchainActor::run(blockchain, account, account_sk, client_tx.clone());
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                actor.handle_message(msg).await
            }
        });

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
}
