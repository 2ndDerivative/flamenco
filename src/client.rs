use std::{
    collections::HashMap,
    io::Cursor,
    num::NonZero,
    ops::DerefMut,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::{Mutex, RwLock, oneshot::Sender},
};

use kenobi::cred::{Credentials, Outbound};

use crate::{
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{
        MessageBody, ReadError, Validation, WriteError, read_202_message, write_202_message,
    },
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    session::{Session202, SessionSetupError},
    sign::SecurityMode,
};

const MINIMUM_TRANSACT_SIZE: u32 = 65536;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum GuestPolicy {
    #[default]
    Disallowed,
    Allowed,
    AllowedInsecurely,
}

#[derive(Debug, Default)]
pub struct Client202 {
    pub requires_signing: bool,
    pub guest_policy: GuestPolicy,
}
impl Client202 {
    pub fn new(requires_signing: bool) -> Arc<Self> {
        Self {
            requires_signing,
            ..Default::default()
        }
        .into()
    }
    pub async fn connect(
        self: Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
        Connection::new(self, addr).await
    }
}

type OutstandingRequests = HashMap<u64, Sender<(SyncHeader202Incoming, Box<[u8]>)>>;
#[derive(Debug)]
pub struct Connection {
    pub(crate) client: Arc<Client202>,
    outstanding_requests: RwLock<OutstandingRequests>,
    message_id: AtomicU64,
    connection: Mutex<TcpStream>,
    max_transaction_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    server_requires_signing: bool,
}
#[derive(Debug)]
pub(crate) enum SignupMessageError {
    Read(crate::message::ReadError),
    Write(crate::message::WriteError),
}
impl Connection {
    pub(crate) async fn signup_message(
        &self,
        mut header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        sign_with_key: Option<[u8; 16]>,
        add_null: bool,
        incoming_validation: Validation,
    ) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), SignupMessageError> {
        let mut connection = self.connection.lock().await;
        header.message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        write_202_message(connection.deref_mut(), sign_with_key, header, msg, add_null)
            .await
            .map_err(SignupMessageError::Write)?;
        read_202_message(connection.deref_mut(), incoming_validation)
            .await
            .map_err(SignupMessageError::Read)
    }
    pub fn max_transaction_size(&self) -> u32 {
        self.max_transaction_size
    }
    pub fn max_read_size(&self) -> u32 {
        self.max_read_size
    }
    pub fn max_write_size(&self) -> u32 {
        self.max_write_size
    }
    pub fn server_requires_signing(&self) -> bool {
        self.server_requires_signing
    }
    pub async fn setup_session(
        self: Arc<Self>,
        credentials: &Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session202>, SessionSetupError> {
        Session202::new(self, credentials, target_spn).await
    }
    pub async fn new(
        client: Arc<Client202>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
        let mut tcp = TcpStream::connect(addr).await?;
        let neg_header = SyncHeader202Outgoing {
            command: Command202::Negotiate,
            credits: 1,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: 0,
        };
        let neg_req = NegotiateRequest202 {
            capabilities: 0,
            security_mode: SecurityMode::None,
        };
        write_202_message(&mut tcp, None, neg_header, &neg_req, false).await?;

        let (header, body) = read_202_message(&mut tcp, Validation::ExpectNone).await?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ConnectError::handle_error_body(code, &body));
        }
        if header.command != Command202::Negotiate || header.message_id != 0 {
            return Err(ConnectError::InvalidMessage);
        }
        let neg_resp = NegotiateResponse::read_from(&mut Cursor::new(body)).await?;
        if neg_resp.max_transact_size < MINIMUM_TRANSACT_SIZE
            || neg_resp.max_read_size < MINIMUM_TRANSACT_SIZE
            || neg_resp.max_write_size < MINIMUM_TRANSACT_SIZE
        {
            return Err(ConnectError::MaxMessageSizeInsufficient);
        }
        let server_requires_signing = neg_resp.security_mode == SecurityMode::SigningRequired;
        match neg_resp.dialect {
            Dialect::SMB2020 => {}
            Dialect::Wildcard => unimplemented!(),
            _ => return Err(ConnectError::ServerChoseUnsupportedDialect),
        }

        Ok(Connection {
            client,
            message_id: 1.into(),
            outstanding_requests: RwLock::default(),
            connection: Mutex::new(tcp),
            max_transaction_size: neg_resp.max_transact_size,
            max_read_size: neg_resp.max_read_size,
            max_write_size: neg_resp.max_write_size,
            server_requires_signing,
        }
        .into())
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    InvalidMessage,
    MaxMessageSizeInsufficient,
    ServerChoseUnsupportedDialect,
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl ServerError for ConnectError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
}
impl From<std::io::Error> for ConnectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<WriteError> for ConnectError {
    fn from(value: WriteError) -> Self {
        match value {
            WriteError::Connection(io) => Self::Io(io),
            WriteError::MessageTooLong => unreachable!(),
        }
    }
}
impl From<ReadError> for ConnectError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::Connection(io) => Self::Io(io),
            ReadError::InvalidSignature
            | ReadError::NotSigned
            | ReadError::InvalidlySignedMessage
            | ReadError::NetBIOS => Self::InvalidMessage,
        }
    }
}
impl From<NegotiateError> for ConnectError {
    fn from(value: NegotiateError) -> Self {
        match value {
            NegotiateError::InvalidDialect | NegotiateError::InvalidSize => Self::InvalidMessage,
            NegotiateError::Io(io) => Self::Io(io),
        }
    }
}
