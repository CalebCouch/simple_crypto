#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error(transparent)]
    BitcoinBip32(#[from] bitcoin::bip32::Error),
    #[error(transparent)]
    HashFromSlice(#[from] bitcoin_hashes::FromSliceError),
    #[error(transparent)]
    Bip324(#[from] crate::bip324::Error),

    #[error("Generic Error {0}: {1}")]
    Generic(String, String),
}

impl Error {
    pub fn err(ctx: &str, err: &str) -> Self {Error::Generic(ctx.to_string(), err.to_string())}
}
