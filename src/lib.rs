pub mod client;
mod error;
pub mod file;
mod header;
mod message;
mod negotiate;
pub mod session;
mod share_name;
mod sign;
pub mod tree;

fn to_wide(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>()
}
