mod grpc;
mod logging;
mod mechs;
mod password;
mod providers;
mod types;
use crate::grpc::saslproto::{
    GetAvailableMechanismsResult,
    AuthenticateArg,
    AuthenticateResult,
};
use crate::grpc::saslproto::sasl_service_server::{SaslService, SaslServiceServer};
use crate::logging::get_default_log4rs_config;
use mechs::PlainAuthProvider;
use tonic::transport::Server;
use smallvec::{SmallVec, smallvec};

pub(crate) struct AuthnServerProvider {
    // pub supported_mechanisms: Vec<String>,

    // TODO: I think you can just do this without dynamic dispatch. Just define an AuthProvider enum.
    pub plain_auth_providers: SmallVec<[Box<dyn PlainAuthProvider>; 4]>,
}

#[tonic::async_trait]
impl SaslService for AuthnServerProvider {

    async fn get_available_mechanisms(
        &self,
        request: tonic::Request<()>,
    ) -> std::result::Result<
        tonic::Response<GetAvailableMechanismsResult>,
        tonic::Status,
    > {
        // if supported_mechanisms.len() != 0 {

        // }
        unimplemented!()
    }

    async fn authenticate(
        &self,
        request: tonic::Request<AuthenticateArg>,
    ) -> std::result::Result<
        tonic::Response<AuthenticateResult>,
        tonic::Status,
    > {
        unimplemented!()
    }

}

/// Every provider MUST support this.
pub trait AuthProvider: Send + Sync {

    fn is_mechanism_supported (&self, _mech: &str) -> bool {
        false
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        vec![]
    }

}

pub(crate) trait UserInfoProvider {

    /// TODO: What should this type be?
    async fn hydrate_user (&self, user: &str) -> bool {
        false
    }

}

#[cfg(not(target_os = "wasi"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log4rs::init_config(get_default_log4rs_config()).unwrap();
    let addr = "127.0.0.1:50051".parse()?;
    let authn_service = AuthnServerProvider{
        plain_auth_providers: smallvec![],
    };
    let authn_server = SaslServiceServer::new(authn_service);
    log::info!("Listening on {}", addr);
    Server::builder()
        .add_service(authn_server)
        .serve(addr).await?;
    Ok(())
}
