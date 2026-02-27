use std::io::Write;

use crate::message::MessageBody;

#[derive(Debug)]
pub struct NegotiateRequest202<'client> {
    pub capabilities: u32,
    pub client_guid: &'client [u8; 16],
}
impl NegotiateRequest202<'_> {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), Error> {
        // structure size
        w.write_all(&36u16.to_le_bytes())?;
        // dialect count
        w.write_all(&1u16.to_le_bytes())?;
        // Empty security mode
        w.write_all(&0u16.to_le_bytes())?;
        // Reserved
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&self.capabilities.to_le_bytes())?;
        w.write_all(self.client_guid.as_slice())?;
        // client start time
        w.write_all(&0u64.to_le_bytes())?;
        // dialect 202
        w.write_all(&0x0202u16.to_le_bytes())?;
        Ok(())
    }
}

impl MessageBody for NegotiateRequest202<'_> {
    type Err = Error;
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}
