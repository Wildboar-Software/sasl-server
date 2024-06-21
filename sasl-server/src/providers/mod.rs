mod memory;
pub use memory::{MemoryIdentityProvider, UserEntry, OTPSecretState};

use crate::types::AttemptId;

/// Every provider MUST support this.
pub trait WithSASLMechanisms {

    fn is_mechanism_supported (&self, _mech: &str) -> bool {
        false
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        vec![]
    }

}

pub trait Stepped {

    async fn get_current_step (
        &self,
        _attempt_id: AttemptId
    ) -> Option<usize> {
        None
    }

}

#[derive(Clone, Debug)]
pub struct AuthProvider {
    pub identifier: String,
    pub provider: AuthProviderType,
}

impl WithSASLMechanisms for AuthProvider {

    fn is_mechanism_supported (&self, mech: &str) -> bool {
        self.provider.is_mechanism_supported(mech)
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        self.provider.supported_mechanisms()
    }

}

#[derive(Clone, Debug)]
pub enum AuthProviderType {
    Memory(MemoryIdentityProvider),
}

impl WithSASLMechanisms for AuthProviderType {

    fn is_mechanism_supported (&self, mech: &str) -> bool {
        match self {
            AuthProviderType::Memory(x) => x.is_mechanism_supported(mech),
        }
    }

    fn supported_mechanisms (&self) -> Vec<String> {
        match self {
            AuthProviderType::Memory(x) => x.supported_mechanisms(),
        }
    }

}