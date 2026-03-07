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
    sync::{Mutex, RwLock},
};

use kenobi::cred::{Credentials, Outbound};

use crate::{
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, Validation, WriteError},
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    session::{Session202, SessionSetupError},
    sign::SecurityMode,
};

mod message;

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

type OutstandingRequests = HashMap<u64, ()>;
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
        header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        incoming_validation: Validation,
    ) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), SignupMessageError> {
        let mut connection = self.connection.lock().await;
        let mut handle = self.outstanding_requests.write().await;
        Self::signup_message_raw(
            handle.deref_mut(),
            connection.deref_mut(),
            &self.message_id,
            header,
            msg,
            add_null,
            incoming_validation,
        )
        .await
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
        let message_id = 0.into();
        let mut pending_requests = HashMap::new();
        let (header, body) = Self::signup_message_raw(
            &mut pending_requests,
            &mut tcp,
            &message_id,
            neg_header,
            &neg_req,
            false,
            Validation::Immediate(None),
        )
        .await
        .map_err(|e| match e {
            SignupMessageError::Read(read_error) => ConnectError::from(read_error),
            SignupMessageError::Write(write_error) => ConnectError::from(write_error),
        })?;
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
            message_id,
            outstanding_requests: RwLock::new(pending_requests),
            connection: Mutex::new(tcp),
            max_transaction_size: neg_resp.max_transact_size,
            max_read_size: neg_resp.max_read_size,
            max_write_size: neg_resp.max_write_size,
            server_requires_signing,
        }
        .into())
    }
    async fn signup_message_raw(
        pending_requests: &mut HashMap<u64, ()>,
        tcp: &mut TcpStream,
        id: &AtomicU64,
        mut header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        incoming_validation: Validation,
    ) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), SignupMessageError> {
        let next_message_id = id.fetch_add(1, Ordering::Relaxed);
        header.message_id = next_message_id;
        let sign_with_key = match incoming_validation {
            Validation::Immediate(k) => k,
            Validation::Delayed(_, _) => None,
        };
        pending_requests.insert(next_message_id, ());
        let result = match message::write_202_message(tcp, sign_with_key, header, msg, add_null)
            .await
            .map_err(SignupMessageError::Write)
        {
            Ok(()) => message::read_202_message(tcp, incoming_validation)
                .await
                .map_err(SignupMessageError::Read),
            Err(e) => Err(e),
        };
        pending_requests.remove(&next_message_id);
        result
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
