use crate::types::{AttemptId, AuthResult, AuthAttempt};
use tonic::async_trait;
use crate::AuthProvider;

#[derive(Clone, Debug)]
pub struct PlainAssertion {
    pub authcid: String,
    pub authzid: Option<String>,
    pub password: String,
}

#[async_trait]
pub(crate) trait PlainAuthProvider: AuthProvider {

    async fn attempt_plain (
        &self,
        attempt: AuthAttempt<PlainAssertion>,
    ) -> AuthResult;

}

// https://www.rfc-editor.org/rfc/rfc6750
pub(crate) trait OAuthBearerProvider {

    async fn attempt_oauth_bearer (
        auth: String,
        authzid: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        kv_pairs: Vec<(String, String)>,
    ) -> Result<(), ()>;

}

// https://www.rfc-editor.org/rfc/rfc2444.html
pub(crate) trait OTPProvider {

    async fn assert_otp_authzid (
        attempt_id: AttemptId,
        authzid: String,
    ) -> Result<(), ()>;

    async fn attempt_otp(
        attempt_id: AttemptId,
        assertion: String,
    ) -> Result<(), ()>;

}