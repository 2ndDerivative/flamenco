use kenobi::cred::Credentials;

#[test]
fn main() {
    use std::time::Duration;

    use flamenco::client::Client202;

    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let client = Client202::default();
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let mut con = client.connect(server).unwrap();
    let _session = con
        .setup_session(&credentials, target_spn.as_deref())
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
}
