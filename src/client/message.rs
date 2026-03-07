use std::{
    io::{Error as IoError, ErrorKind},
    sync::Arc,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const STATUS_PENDING: u32 = 0x00000103;

use crate::{
    header::{FLAG_SIGNED, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, Validation, WriteError},
};

/// Signature validation and netBIOS stuff should be happening here
pub async fn read_202_message<R: AsyncRead + Unpin>(
    r: &mut R,
    validation: Validation,
) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), ReadError> {
    let mut bios_size = [0u8; 4];
    r.read_exact(&mut bios_size)
        .await
        .map_err(ReadError::Connection)?;
    let message_size = match u32::from_be_bytes(bios_size) {
        0..64 => {
            return Err(ReadError::Connection(IoError::new(
                ErrorKind::UnexpectedEof,
                "Not enough data for header",
            )));
        }
        0x0100_0000.. => return Err(ReadError::NetBIOS),
        size => size,
    };
    let mut header_bytes = [0u8; 64];
    r.read_exact(&mut header_bytes)
        .await
        .map_err(ReadError::Connection)?;
    let header = SyncHeader202Incoming::from_bytes(&header_bytes).unwrap();
    let message_body_size = (message_size - 64) as usize;
    let mut message_body = vec![0u8; message_body_size];
    r.read_exact(&mut message_body)
        .await
        .map_err(ReadError::Connection)?;
    let message_body = Arc::from(message_body);
    let is_signed = header.flags & FLAG_SIGNED != 0;
    let arced = Arc::new(header);
    match validation {
        Validation::Immediate(Some(key)) => {
            validate_to_error(&arced, &key, &mut header_bytes, &message_body)
                .map(|()| (arced, message_body))
        }
        Validation::Immediate(None) if !is_signed && arced.signature == [0u8; 16] => {
            Ok((arced, message_body))
        }
        Validation::Delayed(incoming_key, outgoing_ok) => {
            let retained_body = message_body.clone();
            let arced2 = arced.clone();
            tokio::spawn(async move {
                let _ = outgoing_ok.send(
                    async move {
                        let key = incoming_key
                            .await
                            .expect("dropped promised validation handle!");
                        validate_to_error(&arced2, &key, &mut header_bytes, &retained_body)
                    }
                    .await,
                );
            });
            Ok((arced, message_body))
        }
        Validation::Immediate(None) => Err(ReadError::InvalidlySignedMessage),
    }
}

fn validate_to_error(
    header: &SyncHeader202Incoming,
    key: &[u8; 16],
    header_bytes: &mut [u8],
    body_bytes: &[u8],
) -> Result<(), ReadError> {
    let is_signed = header.flags & FLAG_SIGNED != 0;
    if header.message_id != u64::MAX && header.status != STATUS_PENDING {
        if !is_signed {
            Err(ReadError::NotSigned)
        } else if validate_signature(key, &header.signature, header_bytes, body_bytes) {
            Ok(())
        } else {
            Err(ReadError::InvalidSignature)
        }
    } else {
        Ok(())
    }
}

fn validate_signature(
    key: &[u8; 16],
    sig: &[u8; 16],
    header_bytes: &mut [u8],
    body_bytes: &[u8],
) -> bool {
    header_bytes[48..64].fill(0);
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hasher.update(header_bytes);
    hasher.update(body_bytes);
    hasher.finalize().into_bytes()[0..16] == *sig
}

/// Sets the SIGNED flag depending on the signing key being provided
pub async fn write_202_message<W: AsyncWrite + Unpin, M: MessageBody>(
    w: &mut W,
    sign_with_key: Option<[u8; 16]>,
    mut header: SyncHeader202Outgoing,
    body: &M,
    add_null: bool,
) -> Result<(), WriteError> {
    let mut buffer = Vec::with_capacity(64 + body.size_hint());
    if sign_with_key.is_some() {
        header.flags |= FLAG_SIGNED;
    }
    buffer.write_all(&header.to_bytes()).await.unwrap();
    body.write_to(&mut buffer).await.unwrap();
    if add_null {
        buffer.push(0);
    }
    match buffer.len() {
        0..=64 => unreachable!(),
        0x0100_0000.. => Err(WriteError::MessageTooLong),
        len => {
            if let Some(session_key) = sign_with_key {
                let mut hasher = Hmac::<Sha256>::new_from_slice(&session_key).unwrap();
                hasher.update(&buffer);
                let hash_result = hasher.finalize();
                buffer[48..64]
                    .copy_from_slice(hash_result.into_bytes().first_chunk::<16>().unwrap());
            }
            w.write_all(&(len as u32).to_be_bytes())
                .await
                .map_err(WriteError::Connection)?;
            w.write_all(&buffer).await.map_err(WriteError::Connection)?;
            Ok(())
        }
    }
}
