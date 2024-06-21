use std::collections::HashMap;
use crate::grpc::saslproto::authenticate_result::Outcome;
use crate::mechs::{
    AnonymousAssertion,
    AnonymousProvider,
    ExternalAssertion,
    ExternalProvider,
    OTPChallenge,
    PlainAssertion,
    PlainAuthProvider,
    OTPProvider,
};
use crate::grpc::saslproto::{
    AuthenticateResult, UserInformation,
};
use crate::types::{AuthAttempt, AuthResult, UserId, AttemptId};
use crate::password::Password;
use crate::providers::WithSASLMechanisms;
use tonic::async_trait;
use cow_utils::CowUtils;
use rfc2289_otp::{calculate_otp, parse_otp_response, OTPResponse};

use super::Stepped;

fn fail_auth () -> AuthenticateResult {
    AuthenticateResult{
        outcome: Some(Outcome::Decision(false)),
        user_disabled: false,
        all_auth_disabled: false,
        user_info: None,
        ..Default::default()
    }
}

#[derive(Clone, Debug)]
pub struct OTPSecretState {
    pub next_seq_number: usize,
    pub secret: String,
    pub seed: String,
    pub hash_alg: String,
}

#[derive(Clone, Debug)]
pub struct UserEntry {
    pub id: UserId,
    pub password: Option<Password>,
    pub info: UserInformation,
    pub otp: Option<OTPSecretState>,
}

#[derive(Clone, Debug)]
pub struct MemoryIdentityProvider {
    pub users: HashMap<UserId, UserEntry>,

    // TODO: Use TTL or something to evict entries.
    pub otp_challenges: HashMap<AttemptId, (OTPChallenge, UserId)>,
}

impl WithSASLMechanisms for MemoryIdentityProvider {

    fn is_mechanism_supported (&self, mech: &str) -> bool {
        [
            "PLAIN",
            "ANONYMOUS",
            "EXTERNAL",
            "OTP",
        ].contains(&mech)
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        [
            "PLAIN".into(),
            "ANONYMOUS".into(),
            "EXTERNAL".into(),
            "OTP".into(),
        ].into()
    }

}

#[async_trait]
impl PlainAuthProvider for MemoryIdentityProvider {

    async fn attempt_plain (
        &self,
        attempt: &AuthAttempt<PlainAssertion>,
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

#[async_trait]
impl ExternalProvider for MemoryIdentityProvider {

    async fn attempt_external(
        &self,
        attempt: &AuthAttempt<ExternalAssertion>,
    ) -> AuthResult {
        // TODO: Verify asserted X.509 PKC chain.
        // TODO: Make sure the subject name matches the user ID.
        unimplemented!()
    }

}

#[async_trait]
impl AnonymousProvider for MemoryIdentityProvider {

    async fn attempt_anon(
        &self,
        attempt: &AuthAttempt<AnonymousAssertion>,
    ) -> AuthResult {
        if let Some(assertion) = &attempt.assertion {
            let maybe_user = self.users.get(&assertion.to_lowercase()); // TODO: Cow lowercase
            let user = match maybe_user {
                Some(u) => u,
                None => return Ok(AuthenticateResult{
                    outcome: Some(Outcome::Decision(false)),
                    ..Default::default()
                }),
            };
            Ok(AuthenticateResult{
                outcome: Some(Outcome::Decision(true)),
                user_disabled: false,
                all_auth_disabled: false,
                user_info: Some(user.info.clone()),
                ..Default::default()
            })
        } else {
            Ok(AuthenticateResult{
                outcome: Some(Outcome::Decision(true)),
                user_disabled: false,
                all_auth_disabled: false,
                user_info: None,
                ..Default::default()
            })
        }
    }

}

// TODO: More applicable security rules here: https://www.rfc-editor.org/rfc/rfc2243

// #[async_trait]
impl OTPProvider for MemoryIdentityProvider {

    /// Returns Ok(None) if user does not exist.
    async fn get_otp_challenge (
        &mut self,
        attempt_id: AttemptId,
        authcid: &str,
        authzid: Option<&str>,
    ) -> anyhow::Result<Option<OTPChallenge>> {
        let authcid = authcid.cow_to_lowercase();
        let authcid = authcid.as_ref();
        if authzid.is_some_and(|a| a.cow_to_lowercase().as_ref() != authcid) {
            // TODO: Is this correct?
            return Ok(None);
        }
        let maybe_user = self.users.get_mut(authcid);
        if maybe_user.is_none() {
            return Ok(None);
        }
        let user = maybe_user.unwrap();
        if user.otp.is_none() {
            return Ok(None);
        }
        let otp = user.otp.as_mut().unwrap();
        // let seed = rand::random::<u32>();

        let challenge = OTPChallenge{
            alg: otp.hash_alg.to_owned(),
            seq: otp.next_seq_number,
            seed: otp.seed.to_owned(),
        };
        if otp.next_seq_number <= 1 {
            // The user ran out of OTPs in the sequence and requires re-initialization.
            return Ok(None); 
        }
        otp.next_seq_number -= 1;
        self.otp_challenges.insert(attempt_id, (challenge.to_owned(), authcid.to_owned()));
        Ok(Some(challenge))
    }

    // TODO: Remove scopeguard crate? I wanted it for this purpose, but I don't need it now.
    async fn attempt_otp(
        &mut self,
        attempt_id: AttemptId,
        assertion: String,
    ) -> AuthResult {
        let maybe_challenge = self.otp_challenges.remove(&attempt_id);
        if maybe_challenge.is_none() {
            return Ok(fail_auth());
        }
        let (challenge, user_id) = maybe_challenge.unwrap();
        let maybe_user = self.users.get_mut(user_id.as_str());
        if maybe_user.is_none() {
            return Ok(fail_auth());
        }
        let user = maybe_user.unwrap();
        if user.otp.is_none() {
            return Ok(fail_auth());
        }
        let otp = user.otp.as_mut().unwrap();
        let assertion = match parse_otp_response(&assertion) {
            Some(a) => a,
            None => return Ok(AuthenticateResult{
                outcome: Some(Outcome::InvalidAssertion("Invalid response".into())),
                user_disabled: false,
                all_auth_disabled: false,
                user_info: None,
                ..Default::default()
            }),
        };
        let maybe_correct_value = calculate_otp(
            challenge.alg.as_str(),
            otp.secret.as_str(),
            challenge.seed.as_str(),
            challenge.seq,
            None
        );
        if maybe_correct_value.is_none() {
            return Ok(fail_auth())
        }
        let correct_value = maybe_correct_value.unwrap();

        match assertion {
            OTPResponse::Current(x) => {
                let maybe_asserted_otp = x.try_into_bytes();
                if maybe_asserted_otp.is_none() {
                    return Ok(fail_auth());
                }
                let asserted_otp = maybe_asserted_otp.unwrap();
                let authn_success = correct_value == asserted_otp;
                return Ok(AuthenticateResult{
                    outcome: Some(Outcome::Decision(authn_success)),
                    user_disabled: false,
                    all_auth_disabled: false,
                    user_info: if authn_success { Some(user.info.to_owned()) } else { None },
                    ..Default::default()
                });
            },
            OTPResponse::Init(x) => {
                if x.new_seed.len() > 16
                    || !x.new_seed.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Ok(fail_auth());
                }
                let maybe_asserted_otp = x.current_otp.try_into_bytes();
                let maybe_new_otp = x.new_otp.try_into_bytes();
                let is_supported_alg = [ "md4", "md5", "sha1" ].contains(&x.new_alg);
                if maybe_asserted_otp.is_none()
                    || maybe_new_otp.is_none()
                    || !is_supported_alg {
                    return Ok(fail_auth());
                }
                let asserted_otp = maybe_asserted_otp.unwrap();
                let new_otp = maybe_new_otp.unwrap();
                let authn_success = correct_value == asserted_otp;

                if authn_success {
                    let maybe_correct_new_value = calculate_otp(
                        challenge.alg.as_str(),
                        otp.secret.as_str(),
                        challenge.seed.as_str(),
                        challenge.seq,
                        None
                    );
                    if maybe_correct_new_value.is_none() {
                        return Ok(fail_auth());
                    }
                    let correct_new_value = maybe_correct_new_value.unwrap();
                    let new_authn_success = correct_new_value == new_otp;
                    if !new_authn_success {
                        return Ok(fail_auth());
                    }
                    user.otp = Some(OTPSecretState {
                        hash_alg: "sha1".to_owned(),
                        next_seq_number: x.new_seq_num,
                        secret: otp.secret.to_owned(),
                        seed: x.new_seed.into(),
                    });
                }

                return Ok(AuthenticateResult{
                    outcome: Some(Outcome::Decision(authn_success)),
                    user_disabled: false,
                    all_auth_disabled: false,
                    user_info: if authn_success { Some(user.info.to_owned()) } else { None },
                    ..Default::default()
                });
            },
        }
    }

}

impl Stepped for MemoryIdentityProvider {

    // TODO: Should this just return 0 for attempts not started?
    async fn get_current_step (
        &self,
        attempt_id: AttemptId,
    ) -> Option<usize> {
        if self.otp_challenges.get(&attempt_id).is_some() {
            Some(1)
        } else {
            None
        }
    }

}