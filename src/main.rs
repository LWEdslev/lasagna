use std::time::Duration;

use lassecoin::{
    block::Block, blockchain::Blockchain, blockchain_actor::BlockchainActorHandle,
    generate_keypair, SLOT_LENGTH,
};

#[tokio::main]
async fn main() {
    let (sk, vk) = generate_keypair();
    let (_, vk1) = generate_keypair();
    let (_, vk2) = generate_keypair();
    let (_, vk3) = generate_keypair();

    let blockchain = Blockchain::start(
        vec![
            vk.clone().into(),
            vk1.clone().into(),
            vk2.clone().into(),
            vk3.clone().into(),
        ],
        &sk,
    );

    let (c_tx, mut client_rx) = tokio::sync::mpsc::channel(100);

    let bc_handle = BlockchainActorHandle::new(
        blockchain,
        vk.clone().into(),
        sk.clone().into(),
        c_tx.clone(),
    );

    {
        let bc_handle = bc_handle.clone();
        println!("Starting staking!");
        tokio::spawn(async move {
            loop {
                bc_handle.stake().await;
                tokio::time::sleep(Duration::from_millis(SLOT_LENGTH as _)).await;
            }
        });
    }

    {
        tokio::spawn(async move {
            while let Some(msg) = client_rx.recv().await {
                match msg {
                    lassecoin::ClientMessage::Won(_) => {
                        println!("We won!!!");
                    }
                    _ => (),
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_secs(1000)).await;
}

/*
// we make 5 root nodes and then try for 1000 timeslots, see what happens
    let mut blockchains = Vec::new();

    let mut peers = Vec::new();

    let peer_number = 30;

    // generate wallets
    for _ in 0..peer_number {
        peers.push(lassecoin::generate_keypair());
    }

    println!("Generated wallets");
    // generate blockchains
    let blockchain = Blockchain::start(peers.iter().map(|(_, pk)| pk.clone().into()).collect(), &peers[0].0);
    for _ in 0..peer_number {
        blockchains.push(blockchain.clone());
    }

    // check if the blockchains are in sync
    let best_hash = blockchains[0].get_best_hash();
    for blockchain in blockchains.iter() {
        if blockchain.get_best_hash() != best_hash {
            panic!("Blockchains are not in sync {:?}\n-------------------------\n{:?}", &blockchains[0], &blockchain);
        }
    }

    println!("Generated blockchains");

    let max_blocks = 1000;

    for timeslot in 0..max_blocks {
        println!("Timeslot {}", timeslot);
        let mining_blocks = (0..peer_number).map(|i| {
            let (account, account_sk) = peers[i].clone();
            blockchains[i].create_empty_mining_block(account_sk.into(), account.as_ref(), timeslot)
        }).collect::<Vec<_>>();


        let mut winning_blocks: Vec<Block> = Vec::new();

        for i in 0..peer_number {
            let mining_block = &mining_blocks[i];
            let blockchain = &blockchains[i];
            let wallet = peers[i].1.as_ref();
            if blockchain.stake(mining_block, wallet) {
                winning_blocks.push(mining_block.clone());
            }
        }

        if winning_blocks.is_empty() { continue }

        for i in 0..peer_number {
            let blockchain = &mut blockchains[i];
            for block in winning_blocks.iter().cloned() {
                let hash = &hex::encode(block.hash)[0..5];
                //println!("Wallet {i} added block {hash} and it returns {}",
                blockchain.add_block(block);
                //);
            }
        }
    }
    for i in 0..peer_number {
        let blockchain = &blockchains[0];
        let wallet = peers[i].1.as_ref();
        println!("Wallet {i} has a balance of {}", blockchain.get_balance(wallet));
    }
*/
