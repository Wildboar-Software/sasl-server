use crate::types::{AttemptId, AuthResult, AuthAttempt, AuthzId};
use tonic::async_trait;

#[derive(Clone, Debug)]
pub struct PlainAssertion {
    pub authcid: String,
    pub authzid: Option<String>,
    pub password: String,
}

/// Provides the `PLAIN` SASL mechanism
#[async_trait]
pub(crate) trait PlainAuthProvider {

    async fn attempt_plain (
        &self,
        attempt: &AuthAttempt<PlainAssertion>,
    ) -> AuthResult;

}

/// Provides the `OAUTHBEARER` SASL mechanism.
///
/// See [IETF RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)
pub(crate) trait OAuthBearerProvider {

    async fn attempt_oauth_bearer (
        auth: String,
        authzid: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        kv_pairs: Vec<(String, String)>,
    ) -> Result<(), ()>;

}

#[derive(Debug)]
pub struct OTPIdentityAssertion <'a> {
    pub authzid: Option<&'a str>,
    pub authcid: &'a str,
}

#[derive(Debug, Clone)]
pub struct OTPChallenge {
    pub alg: String,
    pub seq: usize,
    pub seed: String,
}

/// Provides the `OTP` SASL mechanism.
///
/// See [IETF RFC 2444](https://www.rfc-editor.org/rfc/rfc2444.html).
pub(crate) trait OTPProvider {

    /// Returns Ok(None) if user does not exist.
    async fn get_otp_challenge (
        &mut self,
        attempt_id: AttemptId,
        authcid: &str,
        authzid: Option<&str>,
    ) -> anyhow::Result<Option<OTPChallenge>>;

    async fn attempt_otp(
        &mut self,
        attempt_id: AttemptId,
        assertion: String,
    ) -> AuthResult;

}

pub type ExternalAssertion = Option<AuthzId>;

/// Provides the `EXTERNAL` SASL mechanism
#[async_trait]
pub(crate) trait ExternalProvider {

    async fn attempt_external (
        &self,
        attempt: &AuthAttempt<ExternalAssertion>,
    ) -> AuthResult;

}

pub type AnonymousAssertion = Option<AuthzId>;

/// Provides the `ANONYMOUS` SASL mechanism
#[async_trait]
pub(crate) trait AnonymousProvider {

    async fn attempt_anon (
        &self,
        attempt: &AuthAttempt<AnonymousAssertion>,
    ) -> AuthResult;

}