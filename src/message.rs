use std::fmt::Debug;

use tokio::{
    io::AsyncWrite,
    sync::oneshot::{Receiver, Sender},
};

#[derive(Debug, Default)]
pub enum Validation {
    #[default]
    ExpectNone,
    Key([u8; 16]),
    Delayed(Receiver<[u8; 16]>, Sender<Result<(), ReadError>>),
}
impl Validation {
    pub fn setup_delayed() -> (
        Self,
        impl FnOnce([u8; 16]) -> Receiver<Result<(), ReadError>>,
    ) {
        let (future_key_in, rx) = tokio::sync::oneshot::channel();
        let (sx, message_is_okay) = tokio::sync::oneshot::channel();
        (Validation::Delayed(rx, sx), |key| {
            future_key_in
                .send(key)
                .expect("validation side channel closed");
            message_is_okay
        })
    }
}
impl From<Option<[u8; 16]>> for Validation {
    fn from(value: Option<[u8; 16]>) -> Self {
        match value {
            Some(key) => Self::Key(key),
            None => Self::ExpectNone,
        }
    }
}

#[derive(Debug)]
pub enum ReadError {
    NetBIOS,
    NotSigned,
    InvalidSignature,
    InvalidlySignedMessage,
    Connection(std::io::Error),
}

#[derive(Debug)]
pub enum WriteError {
    Connection(std::io::Error),
    MessageTooLong,
}

pub(crate) trait MessageBody {
    type Err: Debug;
    async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), Self::Err>;
    fn size_hint(&self) -> usize {
        0
    }
}
