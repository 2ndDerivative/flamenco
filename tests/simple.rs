use std::{cell::RefCell, io::Read, net::TcpStream, sync::Arc, time::Duration};

use flamenco::{client::Client202, session::Session202, tree::TreeConnection};
use kenobi::cred::Credentials;

#[test]
fn main() {
    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let file_path = std::env::var("FLAMENCO_TEST_FILE").unwrap();
    let client = Arc::new(Client202::new(true));
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let client_ref = client.clone();
    let server_copy = server.clone();
    let t = std::thread::spawn(move || {
        let con =
            Client202::connect_with::<_, RefCell<TcpStream>>(client_ref, server_copy).unwrap();
        let credentials = Credentials::new(own_spn.as_deref()).unwrap();
        let mut session = Session202::new(con, &credentials, target_spn.as_deref()).unwrap();
        let mut tree = session.tree_connect(&share_path).unwrap();
        let mut file = tree.open_file(&file_path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        dbg!(String::from_utf8(buf).unwrap());
        std::thread::sleep(Duration::from_millis(200));
    });
    let con = Client202::connect_with::<_, RefCell<TcpStream>>(client, server).unwrap();
    let other_session = Session202::new(con, &credentials, None).unwrap();
    let other_tree = TreeConnection::new(&other_session, "hi").unwrap();
    t.join().unwrap();
}
