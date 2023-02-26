use macros_make_error::make_error2;
use std::str::FromStr;

make_error2!(AuthIdError);

#[derive(
    utoipa::ToSchema, Debug, PartialEq, serde::Deserialize, serde::Serialize, Clone, Default,
)]
pub struct WalletAuthId {
    pub public_key: Vec<u8>,
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
            solana_sdk::pubkey::Pubkey::new(self.public_key.as_slice()).as_ref(),
        )
        .map_err(|z| AuthIdError::GeneralError(z.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_authenticate() {
        let auth_id = serde_json::json!({"public_key":"5czvey8ZkNbEoxU8gjQXLnxpiA5SqQrD6QzVkTbRWSNM","signature":[108,155,193,64,225,219,118,100,131,189,163,89,38,197,126,115,194,101,97,3,44,196,174,176,26,114,38,147,207,36,180,152,123,163,245,87,56,68,130,3,118,190,26,218,100,185,42,19,0,168,89,188,93,26,148,177,159,248,212,251,144,218,136,2,100,104,119,83,54,106,77,51,74,115],"message":[100,104,119,83,54,106,77,51,74,115],"network_id":1});
        let auth_id = serde_json::from_value::<WalletAuthId>(auth_id).unwrap();
        let b = auth_id.authenticate().unwrap();
        println!("{:?}", b);
    }
}
