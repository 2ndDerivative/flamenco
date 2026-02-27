mod error;
mod header;
mod message;
mod negotiate;

#[cfg(test)]
mod test {
    use std::{net::TcpStream, time::Duration};

    use crate::{
        header::{Command202, SyncHeader202},
        message::{read_202_message, write_202_message},
        negotiate::NegotiateRequest202,
    };

    #[test]
    fn test_on_server() {
        let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
        let mut tcp = TcpStream::connect(server).unwrap();
        let client_guid = [0; 16];

        let neg_header = SyncHeader202 {
            status: 0,
            command: Command202::Negotiate,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let neg_req = NegotiateRequest202 {
            capabilities: 0,
            client_guid: &client_guid,
        };
        write_202_message(&mut tcp, &neg_header, &neg_req).unwrap();

        let (header, body) = read_202_message(&mut tcp).unwrap();

        std::thread::sleep(Duration::from_millis(200));
    }
}
