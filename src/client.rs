// we create a client, this is where we combine the network with the core and the cli and handle the messages passed between these actors

use std::{
    fs::{self, ReadDir},
    io::Write,
    net::SocketAddr,
};

use rsa::{
    pkcs1::EncodeRsaPublicKey, pkcs8::der::zeroize::Zeroizing, rand_core::block, RsaPrivateKey,
    RsaPublicKey,
};
use tokio::sync::mpsc;

use crate::{
    blockchain::{self, Blockchain},
    blockchain_actor::BlockchainActorHandle,
    network_actor::NetworkHandle,
    CLIMessage, ClientMessage, ExternalMessage, WALLETS,
};

pub struct ClientActor {
    priv_key: RsaPrivateKey,
    network: NetworkHandle,
    blockchain: Option<BlockchainActorHandle>,
    tx: mpsc::Sender<ClientMessage>,
}

impl ClientActor {
    pub async fn run_root(addr: SocketAddr, root_accounts: Vec<RsaPublicKey>) {
        println!("Please enter your seed phrase:");
        let seed_phrase = Zeroizing::new(crate::cli::read_line().await);
        let sk = crate::cli::key_from_seedphrase(&seed_phrase).expect("key from seedphrase failed");

        let (tx, rx) = mpsc::channel(100);
        let network = NetworkHandle::new(addr, addr, tx.clone());

        let blockchain = Blockchain::start(root_accounts, &sk.clone().into());

        let blockchain_handle =
            BlockchainActorHandle::new(blockchain, sk.to_public_key(), sk.clone(), tx.clone());

        crate::cli::run_cli(tx.clone());
        ClientActor::read_messages(
            Self {
                priv_key: sk,
                network,
                blockchain: Some(blockchain_handle),
                tx: tx.clone(),
            },
            rx,
        );
    }

    pub async fn run(seed_addr: SocketAddr, addr: SocketAddr) {
        println!("Please enter your seed phrase:");
        let seed_phrase = Zeroizing::new(crate::cli::read_line().await);
        let sk = crate::cli::key_from_seedphrase(&seed_phrase).expect("key from seedphrase failed");

        let (tx, rx) = mpsc::channel(100);
        let network = NetworkHandle::new(seed_addr, addr, tx.clone());
        network
            .request_bootstrap()
            .await
            .expect("unable to send Request Bootstrap message");

        crate::cli::run_cli(tx.clone());

        ClientActor::read_messages(
            Self {
                priv_key: sk,
                network,
                blockchain: None,
                tx,
            },
            rx,
        );
    }

    fn read_messages(self, mut rx: mpsc::Receiver<ClientMessage>) {
        tokio::spawn(async move {
            let mut client = self;
            while let Some(msg) = rx.recv().await {
                client.handle_message(msg).await;
            }
        });
    }

    async fn handle_message(&mut self, msg: ClientMessage) {
        match msg {
            ClientMessage::Won(block) => {
                //println!("We won a block");
                self.network.broadcast_block(block).await.unwrap();
            }
            ClientMessage::BalanceOf(wallet, balance) => {
                println!("Wallet has {} las", balance);
            }
            ClientMessage::External(ext_msg) => self.handle_external_message(ext_msg).await,
            ClientMessage::CLI(cli_msg) => self.handle_cli_message(cli_msg).await,
            ClientMessage::Ping => println!("Ping"),
        }
    }

    async fn handle_external_message(&mut self, ext_msg: crate::ExternalMessage) {
        match ext_msg {
            ExternalMessage::Bootstrap(blockchain) => {
                println!("Blockchain bootstrapped");
                if self.blockchain.is_none() {
                    let account_sk = self.priv_key.clone();
                    let blockchain = BlockchainActorHandle::new(
                        blockchain,
                        account_sk.to_public_key(),
                        account_sk,
                        self.tx.clone(),
                    );
                    self.blockchain = Some(blockchain);
                }
            }
            ExternalMessage::BootstrapReqFrom(from) => {
                println!("Sending bootstrap to {from:?}");
                if let Some(ref blockchain_handle) = self.blockchain {
                    self.network
                        .send_bootstraping_message_to(
                            from,
                            blockchain_handle.get_blockchain_copy().await,
                        )
                        .await
                        .unwrap();
                    println!("Sent bootstrap to {from:?}");
                }
            }
            ExternalMessage::BroadcastBlock(block) => {
                println!("Received a block");
                if let Some(ref blockchain_handle) = self.blockchain {
                    blockchain_handle.add_block(block).await;
                }
            },
            ExternalMessage::BroadcastTransaction(t) => {
                if let Some(ref blockchain_handle) = self.blockchain {
                    blockchain_handle.add_transaction(t).await;
                }
            },
        }
    }

    async fn handle_cli_message(&mut self, cli_msg: CLIMessage) {
        match cli_msg {
            CLIMessage::PostTransaction(transaction) => {
                if let Some(ref blockchain) = self.blockchain {
                    self.network.broadcast_transaction(transaction.clone()).await.unwrap();
                    blockchain.add_transaction(transaction).await;
                }
            },
            CLIMessage::CheckBalance(wallet) => {
                if let Some(ref blockchain) = self.blockchain {
                    blockchain.check_balance(wallet).await;
                } else {
                    println!("Blockchain not initialized yet");
                }
            }
        }
    }
}
