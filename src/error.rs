use std::cmp::Ordering;

pub struct ErrorResponse2 {
    bytes: Box<[u8]>,
}
impl ErrorResponse2 {
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let Some((structure_body, error_data)) = b
            .split_at_checked(8)
            .map(|(a, err)| (a.as_array::<8>().unwrap(), err))
        else {
            return Err(Error::UnexpectedEof);
        };
        if u16::from_be_bytes(*structure_body[0..2].as_array().unwrap()) != 9 {
            return Err(Error::InvalidStructureSize);
        }
        if structure_body[2] != 0 {
            return Err(Error::ContextNotSupported);
        }
        // ignore reserved
        let byte_count = u32::from_be_bytes(*structure_body[4..8].as_array().unwrap());
        match (byte_count as usize).cmp(&error_data.len()) {
            Ordering::Less => Err(Error::ExcessTrailingBytes),
            Ordering::Equal => Ok(ErrorResponse2 {
                bytes: error_data.into(),
            }),
            Ordering::Greater => Err(Error::UnexpectedEof),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidStructureSize,
    UnexpectedEof,
    ExcessTrailingBytes,
    ContextNotSupported,
}
