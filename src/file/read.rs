use std::{io::SeekFrom, num::NonZero};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::{
    error::{ErrorResponse2, ServerError},
    file::FileId,
    message::MessageBody,
};

#[derive(Debug)]
pub struct ReadRequest {
    pub length: u32,
    pub offset: u64,
    pub id: FileId,
    pub minimum_count: u32,
}
impl ReadRequest {
    const STRUCTURE_SIZE: u16 = 49;
    pub async fn write_into<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(&Self::STRUCTURE_SIZE.to_le_bytes()).await?;
        w.write_all(&[64 + 16]).await?;
        // in 2.0.2, 2.1 and 3.0 this field must not be used
        w.write_all(&[0]).await?;
        w.write_all(&self.length.to_le_bytes()).await?;
        w.write_all(&self.offset.to_le_bytes()).await?;
        let FileId {
            persistent,
            volatile,
        } = self.id;
        w.write_all(&persistent).await?;
        w.write_all(&volatile).await?;
        w.write_all(&self.minimum_count.to_le_bytes()).await?;
        // Channel
        w.write_all(&0u32.to_le_bytes()).await?;
        // Remaining Bytes
        w.write_all(&0u32.to_le_bytes()).await?;
        // Channel Info Offset
        w.write_all(&0u16.to_le_bytes()).await?;
        // Channel Info Length
        w.write_all(&0u16.to_le_bytes()).await?;
        Ok(())
    }
}
impl MessageBody for ReadRequest {
    type Err = std::io::Error;
    fn size_hint(&self) -> usize {
        48
    }
    async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), Self::Err> {
        self.write_into(w).await
    }
}

#[derive(Debug)]
pub struct ReadResponse(Box<[u8]>);
impl ReadResponse {
    const STRUCTURE_SIZE: u16 = 17;
    pub fn into_inner(self) -> Box<[u8]> {
        self.0
    }
    pub async fn read_from<R: AsyncReadExt + AsyncSeekExt + Unpin>(
        mut r: R,
    ) -> Result<Self, ReadResponseError> {
        if r.read_u16_le().await? != Self::STRUCTURE_SIZE {
            return Err(ReadResponseError::InvalidMessage);
        }
        let mut offset = 0;
        r.read_exact(std::slice::from_mut(&mut offset)).await?;
        r.seek(SeekFrom::Current(1)).await?;
        let data_length = r.read_u32_le().await?;
        let _data_remaining = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(4)).await?;
        if offset < 64 + 16 {
            Err(ReadResponseError::InvalidMessage)
        } else {
            let mut buffer = vec![0; data_length as usize].into_boxed_slice();
            r.seek(SeekFrom::Start((offset - 64) as u64)).await?;
            r.read_exact(buffer.as_mut()).await?;
            Ok(Self(buffer))
        }
    }
}
#[derive(Debug)]
pub enum ReadResponseError {
    Io(std::io::Error),
    InvalidMessage,
}
impl From<std::io::Error> for ReadResponseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub enum ReadFileError {
    Io(std::io::Error),
    InvalidMessage,
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl ReadFileError {
    pub fn collapse_to_io_error(self) -> std::io::Error {
        match self {
            ReadFileError::InvalidMessage => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server sent an invalid message",
            ),
            ReadFileError::Io(io) => io,
            ReadFileError::ServerError { code, body } => {
                dbg!(code, body);
                std::io::Error::other("server sent a protocol error")
            }
        }
    }
}
impl From<std::io::Error> for ReadFileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl ServerError for ReadFileError {
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
}
