mod grpc;
mod logging;
mod mechs;
mod password;
mod providers;
mod types;
use std::collections::HashSet;
use crate::grpc::saslproto::{
    GetAvailableMechanismsResult,
    AuthenticateArg,
    AuthenticateResult,
};
use crate::grpc::saslproto::sasl_service_server::{SaslService, SaslServiceServer};
use crate::logging::get_default_log4rs_config;
use grpc::saslproto::authenticate_result::Outcome;
use grpc::saslproto::Mechanism;
use mechs::{OTPProvider, PlainAssertion, PlainAuthProvider};
use providers::{AuthProvider, AuthProviderType, WithSASLMechanisms};
use tonic::transport::Server;
use types::AuthAttempt;
use ulid::Ulid;
use sha2::{Sha256, Digest};
use base32::Alphabet;
use tokio::sync::Mutex;

#[derive(Debug)]
pub(crate) struct AuthnServerProvider {

    // TODO: Make this private?
    /// This MUST be populated when this is instantiated.
    supported_mechanisms: Vec<String>,
    pub providers: Vec<Mutex<AuthProvider>>, // TODO: Change to RwLock?
}

impl AuthnServerProvider {

    pub fn new (providers: Vec<AuthProvider>) -> Self {
        let mut mechs_set = HashSet::with_capacity(16);
        for provider in &providers {
            for mech in provider.supported_mechanisms() {
                mechs_set.insert(mech);
            }
        }
        AuthnServerProvider {
            providers: providers.into_iter().map(|p| Mutex::new(p)).collect(),
            supported_mechanisms: mechs_set.into_iter().collect(),
        }
    }

}

#[tonic::async_trait]
impl SaslService for AuthnServerProvider {

    async fn get_available_mechanisms(
        &self,
        _request: tonic::Request<()>,
    ) -> std::result::Result<
        tonic::Response<GetAvailableMechanismsResult>,
        tonic::Status,
    > {
        Ok(tonic::Response::new(GetAvailableMechanismsResult{
            mechanisms: self.supported_mechanisms
                .iter()
                .map(|m| Mechanism{
                    name: m.to_owned(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    async fn authenticate(
        &self,
        request: tonic::Request<AuthenticateArg>,
    ) -> std::result::Result<
        tonic::Response<AuthenticateResult>,
        tonic::Status,
    > {
        let req = request.into_inner();
        if req.attempt_id.len() != 0 && req.attempt_id.len() != 16 {
            return Ok(tonic::Response::new(AuthenticateResult{
                outcome: Some(Outcome::InvalidAssertion("Invalid attempt ID".into())),
                ..Default::default()
            }));
        }
        let attempt_id: Option<Ulid> = if req.attempt_id.len() == 16 {
            // I don't know of a more elegant way to do this. Sorry.
            Some(Ulid::from_bytes([
                req.attempt_id[0],
                req.attempt_id[1],
                req.attempt_id[2],
                req.attempt_id[3],
                req.attempt_id[4],
                req.attempt_id[5],
                req.attempt_id[6],
                req.attempt_id[7],
                req.attempt_id[8],
                req.attempt_id[9],
                req.attempt_id[10],
                req.attempt_id[11],
                req.attempt_id[12],
                req.attempt_id[13],
                req.attempt_id[14],
                req.attempt_id[15],
            ]))
        } else {
            None
        };
        // Implement every method on every provider?
        match req.mechanism.as_str() {
            "PLAIN" => {
                let mut params = req.assertion.split(|b| *b == 0);
                let authzid = params.next();
                let authcid = params.next();
                let passwd = params.next();
                // TODO: Check that there are no further parameters
                if passwd.is_none() {
                    return Ok(tonic::Response::new(AuthenticateResult{
                        outcome: Some(Outcome::InvalidAssertion("Not three arguments / two NULLs".into())),
                        ..Default::default()
                    }));
                }
                let authzid = authzid.unwrap().to_vec();
                let authcid = authcid.unwrap().to_vec();
                let passwd = passwd.unwrap().to_vec();
                let authzid = match String::from_utf8(authzid) {
                    Ok(s) => s,
                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                        outcome: Some(Outcome::InvalidAssertion("Non UTF-8 authzid".into())),
                        ..Default::default()
                    })),
                };
                let authcid = match String::from_utf8(authcid) {
                    Ok(s) => s,
                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                        outcome: Some(Outcome::InvalidAssertion("Non UTF-8 authcid".into())),
                        ..Default::default()
                    })),
                };
                let password = match String::from_utf8(passwd) {
                    Ok(s) => s,
                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                        outcome: Some(Outcome::InvalidAssertion("Non UTF-8 passwd".into())),
                        ..Default::default()
                    })),
                };
                let assertion = PlainAssertion {
                    authzid: if authzid.len() == 0 { None } else { Some(authzid) },
                    authcid,
                    password,
                };
                // TODO: Actually fill these in.
                let attempt: AuthAttempt<PlainAssertion> = AuthAttempt {
                    id: Ulid::new(),
                    assertion,
                    ignore_penalty: false,
                    local_addr: None,
                    remote_addr: None,
                    requested_host: None,
                    submitted_securely: None,
                    tls_info: None,
                };
                for p in &self.providers {
                    let provider = p.lock().await;
                    let result = match &provider.provider {
                        AuthProviderType::Memory(p) => p.attempt_plain(&attempt).await,
                    };
                    match result {
                        Ok(r) => return Ok(tonic::Response::new(r)),
                        Err(e) => {
                            // TODO: Log the error.
                        }
                    };
                }
                // None of the providers matched or succeeded.
                return Ok(tonic::Response::new(AuthenticateResult{
                    outcome: Some(Outcome::Decision(false)),
                    ..Default::default()
                }));
            },
            "OTP" => {
                for prov in &self.providers {
                    let mut provider = prov.lock().await;
                    let result = match &mut provider.provider {
                        AuthProviderType::Memory(p) => {
                            if attempt_id.is_some()  {
                                let attempt_id = attempt_id.unwrap();
                                let assertion = match String::from_utf8(req.assertion.clone()) {
                                    Ok(s) => s,
                                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                                        outcome: Some(Outcome::InvalidAssertion("Non string assertion".into())),
                                        ..Default::default()
                                    })),
                                };
                                p.attempt_otp(attempt_id, assertion).await
                            } else {
                                let mut params = req.assertion.split(|b| *b == 0);
                                let authzid = params.next();
                                let authcid = params.next();
                                let authzid = authzid.unwrap().to_vec();
                                let authcid = authcid.unwrap().to_vec();
                                let authzid = match String::from_utf8(authzid) {
                                    Ok(s) => s,
                                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                                        outcome: Some(Outcome::InvalidAssertion("Non UTF-8 authzid".into())),
                                        ..Default::default()
                                    })),
                                };
                                let authcid = match String::from_utf8(authcid) {
                                    Ok(s) => s,
                                    Err(_) => return Ok(tonic::Response::new(AuthenticateResult{
                                        outcome: Some(Outcome::InvalidAssertion("Non UTF-8 authcid".into())),
                                        ..Default::default()
                                    })),
                                };

                                let attempt_id = Ulid::new();
                                let challenge = p.get_otp_challenge(
                                    attempt_id,
                                    &authcid,
                                    if authzid.len() == 0 { None } else { Some(&authzid) },
                                ).await;
                                
                                if challenge.is_err() {
                                    // TODO: Log the error
                                    continue;
                                }
                                let challenge = challenge.unwrap();
                                if challenge.is_none() {
                                    let mut hasher = Sha256::new();
                                    hasher.update(authcid);
                                    hasher.update(b"tjoqitjoqi"); // FIXME: Make a configurable static secret
                                    let hash_result = hasher.finalize();
                                    let fake_seq: u16 = hash_result[0] as u16
                                        + hash_result[1] as u16
                                        + hash_result[2] as u16
                                        + hash_result[3] as u16
                                        ;
                                    let fake_seed_bytes: [u8; 4] = [
                                        hash_result[4],
                                        hash_result[5],
                                        hash_result[6],
                                        hash_result[7],
                                    ];
                                    let fake_seed = base32::encode(Alphabet::Rfc4648 { padding: true }, &fake_seed_bytes);
                                    let fake_challenge = format!("otp-sha1 {} {} ext", fake_seq, fake_seed);
                                    /* If the user does not exist, we do not
                                    return a failure. Instead, we return a fake
                                    challenge so as to avoid revealing what
                                    usernames are valid or not. We generate a
                                    sequence number using a hash of the username
                                    and a server secret, and we do the same for
                                    the seed string as well. */
                                    return Ok(tonic::Response::new(AuthenticateResult{
                                        outcome: Some(Outcome::Continuation(fake_challenge.into_bytes())),
                                        ..Default::default()
                                    }))
                                }
                                let challenge = challenge.unwrap();
                                let challenge_str = format!("otp-{} {} {}", challenge.alg, challenge.seq, &challenge.seed);
                                return Ok(tonic::Response::new(AuthenticateResult{
                                    outcome: Some(Outcome::Continuation(challenge_str.into_bytes())),
                                    ..Default::default()
                                }))
                            }
                        },
                    };
                    match result {
                        Ok(r) => return Ok(tonic::Response::new(r)),
                        Err(e) => {
                            // TODO: Log the error.
                        }
                    };
                }
                // None of the providers matched or succeeded.
                return Ok(tonic::Response::new(AuthenticateResult{
                    outcome: Some(Outcome::Decision(false)),
                    ..Default::default()
                }));
            },
            _ => Ok(tonic::Response::new(AuthenticateResult{
                // TODO: I think you could use a way to explicitly signal "method not supported."
                outcome: Some(Outcome::Decision(false)),
                ..Default::default()
            }))
        }
    }

}

pub(crate) trait UserInfoProvider {

    /// TODO: What should this type be?
    async fn hydrate_user (&self, _user: &str) -> bool {
        false
    }

}

#[cfg(debug_assertions)] 
fn get_initial_providers () -> Vec<AuthProvider> {
    use std::collections::HashMap;
    use password::Password;

    use crate::providers::{MemoryIdentityProvider, UserEntry, OTPSecretState};
    use crate::grpc::saslproto::UserInformation;

    log::warn!("You are using a debug build which is INSECURE. Do NOT use this in production.");

    let user_id = "test";
    let pwd = Password{
        algorithm: password::PBKDFAlgorithm::InsecureNone,
        ciphertext: b"asdf".to_vec(),
    };
    let otp = OTPSecretState {
        next_seq_number: 499,
        secret: "hamburger".into(),
        seed: "carrot".into(),
        hash_alg: "sha1".into(),
    };
    let test_user = UserEntry {
        id: user_id.into(),
        info: UserInformation{
            user_id: user_id.into(),
            display_name: "Testeroo Besteroo".into(),
            ..Default::default()
        },
        password: Some(pwd),
        otp: Some(otp),
    };

    let mut users = HashMap::with_capacity(1);
    users.insert(user_id.into(), test_user);
    vec![
        AuthProvider{
            identifier: "Test".into(),
            provider: AuthProviderType::Memory(MemoryIdentityProvider {
                users,
                otp_challenges: HashMap::new(),
            })
        }
    ]
}

#[cfg(not(debug_assertions))] 
fn get_initial_providers () -> Vec<AuthProvider> {
    vec![]
}

#[cfg(not(target_os = "wasi"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log4rs::init_config(get_default_log4rs_config()).unwrap();
    let addr = "127.0.0.1:50051".parse()?;
    let authn_service = AuthnServerProvider::new(get_initial_providers());
    let authn_server = SaslServiceServer::new(authn_service);
    log::info!("Listening on {}", addr);
    Server::builder()
        .add_service(authn_server)
        .serve(addr).await?;
    Ok(())
}
