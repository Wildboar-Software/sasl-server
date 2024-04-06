use std::collections::HashMap;
use crate::grpc::saslproto::authenticate_result::Outcome;
use crate::mechs::{PlainAuthProvider, PlainAssertion};
use crate::grpc::saslproto::{
    AuthenticateResult, UserInformation,
};
use crate::types::{AuthAttempt, AuthResult, UserId};
use crate::password::Password;
use crate::AuthProvider;
use tonic::async_trait;

// TODO: Support OTP.
#[derive(Clone, Debug)]
pub struct UserEntry {
    pub id: UserId,
    pub password: Option<Password>,
    pub info: UserInformation,
}

#[derive(Clone, Debug)]
pub struct MemoryIdentityProvider {
    pub users: HashMap<UserId, UserEntry>,
}

impl AuthProvider for MemoryIdentityProvider {

    fn is_mechanism_supported (&self, mech: &str) -> bool {
        mech == "PLAIN"
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        vec!["PLAIN".to_string()]
    }

}

#[async_trait]
impl PlainAuthProvider for MemoryIdentityProvider {

    async fn attempt_plain (
        &self,
        attempt: AuthAttempt<PlainAssertion>,
    ) -> AuthResult {
        match &attempt.assertion.authzid {
            Some(authzid) => {
                let authzid = authzid.to_lowercase(); // TODO: Cow lowercase
                let authcid = attempt.assertion.authcid.to_lowercase(); // TODO: Cow lowercase

                // This implementation does not support separate authorization identities.
                if authcid != authzid {
                    return Ok(AuthenticateResult{
                        outcome: Some(Outcome::Decision(false)),
                        ..Default::default()
                    });
                }
            },
            _ => {},
        };
        let maybe_user = self.users.get(&attempt.assertion.authcid.to_lowercase()); // TODO: Cow lowercase
        let user = match maybe_user {
            Some(u) => u,
            None => return Ok(AuthenticateResult{
                outcome: Some(Outcome::Decision(false)),
                ..Default::default()
            }),
        };
        let stored_password = match &user.password {
            Some(p) => p,
            None => return Ok(AuthenticateResult{
                outcome: Some(Outcome::Decision(false)),
                ..Default::default()
            }),
        };
        let asserted_password_valid = stored_password.check_str(&attempt.assertion.password)?;
        Ok(AuthenticateResult{
            outcome: Some(Outcome::Decision(asserted_password_valid)),
            user_disabled: false,
            all_auth_disabled: false,
            user_info: Some(user.info.clone()),
            ..Default::default()
        })
    }

}