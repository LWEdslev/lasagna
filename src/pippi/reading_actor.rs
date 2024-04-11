use crate::pippi::{Message, PippiError, Result};
use tokio::{
    io::AsyncReadExt,
    net::tcp::OwnedReadHalf,
    sync::{mpsc, oneshot},
};

struct ReadingActor {
    reader: OwnedReadHalf,
    receiver: tokio::sync::mpsc::Receiver<ReadingActorMessage>,
}

impl ReadingActor {
    fn new(
        receiver: tokio::sync::mpsc::Receiver<ReadingActorMessage>,
        reader: OwnedReadHalf,
    ) -> Self {
        Self { reader, receiver }
    }

    async fn run(mut actor: ReadingActor) -> Result<()> {
        while let Some(msg) = actor.receiver.recv().await {
            actor.handle_message(msg).await?;
        }
        Ok(())
    }

    async fn read(reader: &mut OwnedReadHalf) -> Result<Message> {
        let mut length_buf = [0; 4];
        reader
            .readable()
            .await
            .map_err(|_| PippiError::WritingActorError)?;
        reader
            .read_exact(&mut length_buf)
            .await
            .map_err(|_| PippiError::ReadingActorError)?;
        let length = u32::from_be_bytes(length_buf);
        let mut buf = vec![0; length as usize];
        let n = reader
            .read_exact(&mut buf)
            .await
            .map_err(|_| PippiError::ReadingActorError)?;
        let message = Message::from_bytes(&buf[..n]).map_err(|_| PippiError::ReadingActorError)?;
        Ok(message)
    }

    async fn handle_message(&mut self, msg: ReadingActorMessage) -> Result<()> {
        match msg {
            ReadingActorMessage::Read { reply_to } => {
                let msg = Self::read(&mut self.reader).await;
                reply_to
                    .send(msg)
                    .map_err(|_| PippiError::WritingActorError)?;
                Ok(())
            }
            ReadingActorMessage::Kill => {
                self.receiver.close();
                Ok(())
            }
        }
    }
}

enum ReadingActorMessage {
    Read {
        reply_to: oneshot::Sender<Result<Message>>,
    },
    Kill,
}

#[derive(Debug, Clone)]
pub struct ReadingActorHandle {
    sender: tokio::sync::mpsc::Sender<ReadingActorMessage>,
}

impl ReadingActorHandle {
    pub fn new(reader: OwnedReadHalf) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        let actor = ReadingActor::new(receiver, reader);
        tokio::spawn(ReadingActor::run(actor));
        Self { sender }
    }

    pub async fn kill(&self) -> Result<()> {
        self.sender
            .send(ReadingActorMessage::Kill)
            .await
            .map_err(|_| PippiError::ReadingActorError)
    }

    pub async fn read(&self) -> Result<Message> {
        let (tx, rx) = oneshot::channel();
        let msg = ReadingActorMessage::Read { reply_to: tx };
        self.sender
            .send(msg)
            .await
            .map_err(|_| PippiError::ReadingActorError)?;
        rx.await.map_err(|_| PippiError::ReadingActorError)?
    }
}
