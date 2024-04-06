use scrypt::{
    scrypt,
    Params as ScryptParams,
};
use constant_time_eq::constant_time_eq;

#[derive(Clone, Debug)]
pub enum PBKDFAlgorithm {
    #[cfg(debug_assertions)]
    InsecureNone, // This is just here for easy testing and development.
    Scrypt((ScryptParams, Vec<u8>)),
}

#[derive(Clone, Debug)]
pub struct Password {
    pub ciphertext: Vec<u8>,
    pub algorithm: PBKDFAlgorithm,
}

fn transform_scrypt (password: &[u8], salt: &[u8], params: &ScryptParams) -> anyhow::Result<Vec<u8>> {
    let mut output: Vec<u8> = Vec::with_capacity(64);
    scrypt(password, salt, params, output.as_mut_slice())?;
    Ok(output)
}

impl Password {

    pub fn check_str (&self, password: &str) -> anyhow::Result<bool> {
        let encoded = match &self.algorithm {
            #[cfg(debug_assertions)]
            PBKDFAlgorithm::InsecureNone => return Ok(constant_time_eq(self.ciphertext.as_slice(), password.as_bytes())),
            PBKDFAlgorithm::Scrypt((params, salt)) => transform_scrypt(password.as_bytes(), &salt, &params)?,
        };
        Ok(constant_time_eq(self.ciphertext.as_slice(), encoded.as_slice()))
    }

}