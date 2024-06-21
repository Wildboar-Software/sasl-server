use std::net::SocketAddr;
use ulid::Ulid;

use crate::grpc::saslproto::{AuthenticateResult, TlsInformation};

pub type UserId = String;
pub type AuthzId = UserId;
pub type AttemptId = Ulid;

#[derive(Clone, Debug)]
pub struct AuthAttempt <AssertionType>
    where AssertionType: Clone {

    /// The attempt ID
    pub id: AttemptId,

    /// The assertion value
    pub assertion: AssertionType,

    /// The address of the SASL client / protected resource.
    pub local_addr: Option<SocketAddr>,

    /// The address of the authenticating party.
    pub remote_addr: Option<SocketAddr>,

    /// Whether the assertion was submitted over TLS or something like that.
    pub submitted_securely: Option<bool>,

    /// The requested host, such as is sent via TLS SNI or the HTTP Host header.
    pub requested_host: Option<String>,

    /// Information about the TLS connection used by the authenticating party.
    pub tls_info: Option<TlsInformation>,

    /// If true, do not increment the number of invalid attempts.
    pub ignore_penalty: bool,
}

pub type AuthResult = anyhow::Result<AuthenticateResult>;


impl <T> Default for AuthAttempt<T>
    where T: Default + Clone {

    fn default() -> Self {
        AuthAttempt {
            id: Ulid::new(),
            assertion: T::default(),
            ignore_penalty: false,
            local_addr: None,
            remote_addr: None,
            requested_host: None,
            submitted_securely: None,
            tls_info: None,
        }
    }

}