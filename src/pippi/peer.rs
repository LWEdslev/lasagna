use std::{collections::HashSet, marker::PhantomData, net::SocketAddr, time::Duration};

use crate::ClientMessage;
use crate::{
    pippi::{
        connectionmap::ConnectionMap,
        flooding_set_actor::FloodingSetHandle,
        heartbeat::HeartbeatHandle,
        message_handling::{DefaultMessageHandlingStrategy, MessageHandlingStrategy},
        peerset::Peerset,
        reading_actor::ReadingActorHandle,
        writing_actor::WritingActorHandle,
        Message, MessageContent, PippiError, Result, MAX_PEERS, PEER_WALK_DEPTH, THROTTLE_MESSAGES,
        THROTTLE_PERIOD,
    },
    ExternalMessage,
};
use rand::Rng;
use tokio::{
    net::TcpStream,
    sync::mpsc,
};

#[derive(Clone)]
pub struct Peer<M: MessageHandlingStrategy = DefaultMessageHandlingStrategy> {
    pub(crate) address: SocketAddr,
    pub(crate) peerset: Peerset,
    pub(crate) connections: ConnectionMap,
    pub(crate) flooding_set: FloodingSetHandle,
    pub(crate) heartbeat: HeartbeatHandle,
    app_channel: mpsc::Sender<ClientMessage>,
    message_handling: PhantomData<M>,
}

impl<M> Peer<M>
where
    M: MessageHandlingStrategy,
{
    pub(crate) fn new_no_startup(
        addr: SocketAddr,
        app_channel: mpsc::Sender<ClientMessage>,
    ) -> Self {
        Self {
            address: addr,
            peerset: Peerset::empty(),
            connections: ConnectionMap::new(),
            flooding_set: FloodingSetHandle::new(),
            heartbeat: HeartbeatHandle::new(),
            app_channel,
            message_handling: PhantomData,
        }
    }

    pub fn new(addr: SocketAddr, app_channel: mpsc::Sender<ClientMessage>) -> Result<Self> {
        let peer = Peer::new_no_startup(addr, app_channel);
        peer.listen_for_connections()?;
        peer.run_peer_walk();
        peer.run_heartbeat_protocol();
        Ok(peer)
    }

    pub async fn get_peerset(&self) -> HashSet<SocketAddr> {
        self.peerset.get_copy().await
    }

    pub(crate) async fn connections_len(&self) -> usize {
        self.connections.len().await
    }

    pub(crate) fn listen_for_connections(&self) -> Result<()> {
        let peer = self.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(peer.address)
                .await
                .expect("unable to create listener");
            loop {
                // if someone is trying to spam us connections we don't allow them to ddos us
                while peer.connections_len().await > crate::pippi::MAX_CONNECTIONS {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
                if let Ok((stream, _)) = listener.accept().await {
                    peer.handle_stream(stream);
                };
            }
        });

        Ok(())
    }

    async fn add_connection(
        &self,
        addr: SocketAddr,
        reader: ReadingActorHandle,
        writer: WritingActorHandle,
    ) {
        self.connections
            .insert_if_not_present(addr, (reader, writer))
            .await
    }

    pub(crate) fn handle_stream(&self, stream: tokio::net::TcpStream) {
        let peer = self.clone();
        tokio::spawn(async move {
            let (reader, writer) = stream.into_split();
            let reader = ReadingActorHandle::new(reader);
            let message = reader.read().await;

            let Ok(message) = message else {
                reader
                    .kill()
                    .await
                    .expect("error while trying to kill reader");
                return;
            };

            let from = &message.from;
            match message.content {
                MessageContent::Contact => {
                    let writer = WritingActorHandle::new(writer);
                    peer.add_connection(*from, reader.clone(), writer).await;
                    peer.handle_connection(reader);
                    peer.heartbeat.update(*from).await;
                }
                _ => {
                    println!(
                        "Contact expected but {} received {:?} from {}",
                        peer.address.port(),
                        message.content,
                        from.port()
                    );
                    reader
                        .kill()
                        .await
                        .expect("error while trying to kill reader");
                }
            }
        });
    }

    pub(crate) fn handle_connection(&self, reader: ReadingActorHandle) {
        let peer = self.clone();
        tokio::spawn(async move {
            let mut messages_since_reset = 0;
            let mut last_reset = crate::pippi::get_unix_time();

            loop {
                let msg = match reader.read().await {
                    Err(PippiError::ReadingActorError) => {
                        break;
                    }
                    Err(e) => {
                        println!("Error: {e}");
                        continue;
                    }
                    Ok(msg) => msg,
                };

                // throttling mechanism
                messages_since_reset += 1;
                if messages_since_reset == THROTTLE_MESSAGES {
                    // if we have acheived enough messages
                    let sys_time = crate::pippi::get_unix_time();
                    if last_reset + THROTTLE_PERIOD > sys_time {
                        // in enough time
                        let time_to_sleep = last_reset + THROTTLE_PERIOD - sys_time;

                        // we sleep before handling any more message
                        tokio::time::sleep(Duration::from_millis(time_to_sleep as u64)).await;
                    }
                    messages_since_reset = 0;
                    last_reset = crate::pippi::get_unix_time();
                }

                match M::handle_message(&peer, msg).await {
                    Ok(_) => (),
                    Err(PippiError::NotFound) => (), // this occurs when handling a message where we dropped the peer
                    Err(e) => panic!("{e}"),
                }
            }
        });
    }

    pub(crate) async fn establish_contact(&self, to: &SocketAddr) -> Result<()> {
        if self.connections.get(to).await.is_none() {
            let stream = TcpStream::connect(to).await?;
            let (reader, writer) = stream.into_split();
            let writer = WritingActorHandle::new(writer);
            let reader = ReadingActorHandle::new(reader);
            self.handle_connection(reader.clone());
            self.connections.insert(*to, (reader, writer)).await;
        };
        self.send_to(
            &Message::new_direct_message(&self.address, MessageContent::Contact),
            to,
        )
        .await?;
        Ok(())
    }

    pub async fn join_network(&self, seed_node: &SocketAddr) -> Result<()> {
        self.establish_contact(seed_node).await?;

        self.peerset.add_peer(*seed_node).await;

        let message = Message::new_direct_message(&self.address, MessageContent::AddMe);
        self.send_to(&message, seed_node).await?;

        Ok(())
    }

    pub async fn app_message(&self, app_message: ExternalMessage) {
        self.app_channel.send(app_message.into()).await.unwrap();
    }

    pub(crate) async fn send_to(&self, message: &Message, to: &SocketAddr) -> Result<()> {
        if let Some((_, writer)) = self.connections.get(to).await {
            writer.send_message(message.clone()).await?;
            Ok(())
        } else {
            Err(PippiError::NotFound)
        }
    }

    pub(crate) async fn broadcast_to_peerset(&self, msg: Message) {
        let peer = self.clone();
        let peerset = peer.peerset.get_copy().await;
        for otherpeer in peerset {
            peer.send_to(&msg, &otherpeer).await.unwrap_or(());
        }
    }

    pub(crate) fn run_peer_walk(&self) {
        let peer = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let inner_peerset = peer.peerset.inner.read().await;
                let peerset_len = inner_peerset.len();
                if peerset_len >= MAX_PEERS - 1 || peerset_len == 0 {
                    continue;
                }
                let random_index = rand::thread_rng().gen_range(0..peerset_len);
                let random_peer = *inner_peerset
                    .get_copy()
                    .iter()
                    .nth(random_index)
                    .expect("unreachable");

                let message = Message::new_direct_message(
                    &peer.address,
                    MessageContent::PeersetRelayRequest {
                        origin: peer.address,
                        counter: PEER_WALK_DEPTH,
                    },
                );
                peer.establish_contact(&random_peer).await.unwrap();
                peer.send_to(&message, &random_peer).await.unwrap();

                drop(inner_peerset);
            }
        });
    }

    /// Used for flooding blockchain messages, such as transaction or block
    pub async fn flood(&self, message: ExternalMessage) {
        let message = Message::new_flood_message(&self.address, MessageContent::App(message));
        let peers = self.peerset.get_copy().await;
        for to in peers {
            self.send_to(&message, &to)
                .await
                .unwrap_or_else(|_| println!("unable to flood message"));
        }
    }

    /// Used for sending a direct blockchain message such as a bootstrap
    pub async fn send_direct_client_message(&self, to: SocketAddr, message: ExternalMessage) {
        let message = Message::new_direct_message(&self.address, MessageContent::App(message));
        self.send_to(&message, &to)
            .await
            .unwrap_or_else(|_| println!("unable to send direct client message"));
    }

    fn run_heartbeat_protocol(&self) {
        {
            let peer = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(1_000)).await;
                    let deads = peer.heartbeat.take_dead().await;
                    for dead in deads {
                        peer.peerset.remove(&dead).await;
                        if let Some((r, w)) = peer.connections.remove(&dead).await {
                            r.kill().await.unwrap_or(());
                            w.kill().await.unwrap_or(());
                        };
                    }
                }
            });
        }

        let peer = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(crate::pippi::heartbeat::HEARTBEAT)).await;
                let message = Message::new_direct_message(&peer.address, MessageContent::Heartbeat);
                peer.broadcast_to_peerset(message).await;
            }
        });
    }

    pub async fn shutdown(&self) {
        self.connections.shutdown().await.unwrap();
        let peerset = self.peerset.get_copy().await;
        for peer in peerset {
            self.peerset.remove(&peer).await;
        }
    }
}
