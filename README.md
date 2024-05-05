# Lasagna 
Pet proof of stake blockchain
## How to start
To run use `cargo run --release` and enter your port forwarded address.
Then enter the address of another node on the network (so you can get connected to the entire network and boostrapped).
Then enter a path to the folder in which you keep the wallet pems. These are named such that `balance alice` will use the wallet of alice.pem in the specified folder.
You will also be prompted to enter your seed phrase.
Then wait for the blockchain to be bootstrapped.

## How to use CLI
The following commands are currently available:
- `balance <ADDRESS>` example: `balance alice` will write the current balance of alice's account 
- `send <AMOUNT> <TO>` example: `send 50 bob` will broadcast a transaction from where you send 50 las to bob. Note that the transaction will only be proccessed when it is included in a new block.

## Constants
- Timeslot length: `10 seconds`
- Average block time: `100 seconds`
- Chance of winning in a timeslot: `10% * yourBalance / entireLedgerBalance`. 
    - Example: you have 10% of the entire blockchain worth so you win on average 1% of the timeslots (once every 1000 seconds).
- Block reward: `50 las`
- Transaction fee: `1 las`
- Root accounts reward: `300 las`