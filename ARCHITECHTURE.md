# Description of the overall architechture
# pippi/
Contains the peer-to-peer network. Mainly designed through actor models.
`peer.rs` is the entry point and central functionality of the p2p modules.
`peerset.rs` handles the peerset.
`heartbeat.rs` holds the heartbeat protocol.
# client.rs
Is responsible for communication between actors, and handling client functionality
# blockchain.rs 
Contains the blockchain functionality using some other modules.
# clock_watch.rs
Is a view which notifies timeslot events
# bin/
Contains the binaries