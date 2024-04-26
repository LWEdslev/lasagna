use tokio::{io::AsyncWriteExt, net::tcp::OwnedWriteHalf, sync::mpsc};

use crate::pippi::{Message, PippiError, Result};

struct WritingActor {
    writer: OwnedWriteHalf,
    receiver: tokio::sync::mpsc::Receiver<WritingActorMessage>,
}

impl WritingActor {
    fn new(receiver: mpsc::Receiver<WritingActorMessage>, write: OwnedWriteHalf) -> Self {
        Self {
            writer: write,
            receiver,
        }
    }

    async fn run(mut actor: WritingActor) {
        while let Some(msg) = actor.receiver.recv().await {
            match actor.handle_message(msg).await {
                Ok(()) => (),
                Err(_) => (),
            }
        }
    }

    async fn handle_message(&mut self, msg: WritingActorMessage) -> Result<()> {
        match msg {
            WritingActorMessage::Write { message } => {
                let mut debug_bool = false;
                match message.content {
                    crate::pippi::MessageContent::App(ref ext_msg) => {
                        match ext_msg {
                            crate::ExternalMessage::Bootstrap(_) => debug_bool = true,
                            _ => (),
                        }
                    },
                    _ => (),
                }
                if debug_bool { println!("yippa"); }
                let bytes = message.to_bytes()?;
                self.writer.writable().await?;
                let length = bytes.len() as u64; // 4 bytes
                if debug_bool { println!("sending length {length}"); }
                let length_bytes = length.to_be_bytes();
                self.writer.write_all(&length_bytes).await?;
                self.writer.write_all(&bytes).await?;
                if debug_bool { println!("dibbidooo"); }
                Ok(())
            }
            WritingActorMessage::Kill => {
                self.receiver.close();
                Ok(())
            }
        }
    }
}

enum WritingActorMessage {
    Write { message: Message },
    Kill,
}

#[derive(Debug, Clone)]
pub struct WritingActorHandle {
    sender: tokio::sync::mpsc::Sender<WritingActorMessage>,
}

impl WritingActorHandle {
    pub fn new(writer: OwnedWriteHalf) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        let actor = WritingActor::new(receiver, writer);
        tokio::spawn(WritingActor::run(actor));
        Self { sender }
    }

    pub async fn send_message(&self, msg: Message) -> Result<()> {
        let msg = WritingActorMessage::Write { message: msg };
        self.sender
            .send(msg)
            .await
            .map_err(|_| PippiError::WritingActorError)
    }

    pub async fn kill(&self) -> Result<()> {
        self.sender
            .send(WritingActorMessage::Kill)
            .await
            .map_err(|_| PippiError::WritingActorError)
    }
}
