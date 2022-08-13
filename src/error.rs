use digest::crypto_common::InvalidLength;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CognitoSrpError {
    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("illegal argument: {0}")]
    IllegalArgument(String),
}

impl From<InvalidLength> for CognitoSrpError {
    fn from(err: InvalidLength) -> CognitoSrpError {
        CognitoSrpError::CryptoError(err.to_string())
    }
}
