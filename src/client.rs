use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};

use uuid::Uuid;

use crate::Connection;

#[derive(Clone, Default)]
pub struct Client {
    connections: ClientInner,
    client_guid: Uuid,
}
#[derive(Default)]
struct ClientInner(Arc<Mutex<HashMap<SocketAddr, Weak<Connection>>>>);
impl Clone for ClientInner {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl Client {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn client_id(&self) -> Uuid {
        self.client_guid
    }
    pub(crate) fn register_connection(&self, con: SocketAddr, connection: Weak<Connection>) {
        self.connections.0.lock().unwrap().insert(con, connection);
    }
    pub(crate) fn deregister_connection(&self, con: SocketAddr) {
        self.connections.0.lock().unwrap().remove(&con);
    }
}
