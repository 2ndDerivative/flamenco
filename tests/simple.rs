use flamenco::{client::Client202, session::Session202, tree::TreeConnection};
use kenobi::cred::Credentials;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread")]
async fn main() {
    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let file_path = std::env::var("FLAMENCO_TEST_FILE").unwrap();
    let client = Client202::new(true);
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let server_copy = server.clone();
    let con = client.connect(server_copy).await.unwrap();
    let other_session = Session202::new(con, &credentials, target_spn.as_deref())
        .await
        .unwrap();
    let other_tree = TreeConnection::new(other_session, &share_path)
        .await
        .unwrap();
    let mut file2 = other_tree.open_file(&file_path).await.unwrap();
    eprintln!("Opened file");
    let mut s = String::new();
    dbg!(file2.read_to_string(&mut s).await).unwrap();
    println!("Read file: {s}");
}
