use macros_make_error::make_error2;
use std::str::FromStr;

make_error2!(AuthIdError);

#[derive(
    utoipa::ToSchema, Debug, PartialEq, serde::Deserialize, serde::Serialize, Clone, Default,
)]
pub struct WalletAuthId {
    pub public_key: String,
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
    pub network_id: i32,
    pub id: Option<i32>,
}

impl WalletAuthId {
    pub fn authenticate(&self) -> Result<bool, AuthIdError> {
        nacl::sign::verify(
            &self.signature.as_slice(),
            &self.message.as_slice(),
            solana_sdk::pubkey::Pubkey::from_str(self.public_key.as_str())
                .map_err(AuthIdError::from_general)?
                .as_ref(),
        )
        .map_err(|z| AuthIdError::GeneralError(z.message))
    }
}
