use p256::{SecretKey,};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use tracing::info;
use crate::crypt;
use crate::conf;
use crate::utility;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MyAddress {
    pub private_key: String,
    pub public_key: String,
    pub address: String,
}

pub fn init_address() {
    let _ = crypt::create_secret_key();

    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();

    let secret_key = secret_pem.parse::<SecretKey>().unwrap();
    let private_key_serialized = hex::encode(&secret_key.to_bytes());

    let public_key = secret_key.public_key();
    let public_key_serialized = hex::encode(&public_key.to_sec1_bytes());
    let address = crypt::create_address(&public_key);  

    // log
    info!("Address Created. private key: {}, public key: {}, address: {}", private_key_serialized, public_key_serialized, address);

    let _ = utility::create_qrcode(&address);
}

pub fn get_public_key() -> Result<String> {
    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();
    let secret_key = secret_pem.parse::<SecretKey>().unwrap();

    let public_key = secret_key.public_key();
    let public_key_serialized = hex::encode(&public_key.to_sec1_bytes());

    Ok(public_key_serialized)
}

pub fn get_address() -> Result<MyAddress> {

    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();

    let secret_key = secret_pem.parse::<SecretKey>().unwrap();
    let private_key_serialized = hex::encode(&secret_key.to_bytes());

    let public_key = secret_key.public_key();
    let public_key_serialized = hex::encode(&public_key.to_sec1_bytes());
    let address = crypt::create_address(&public_key);  

    let my_address = MyAddress { private_key: private_key_serialized.to_string(), public_key: public_key_serialized.to_string(), address: address };
    Ok(my_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey,Signature,VerifyingKey};
    use p256::ecdsa::signature::{Verifier,Signer};

    #[test]
    fn test_get_public_key() {
        let public_key = get_public_key().unwrap();
        let public_key_decode = hex::decode(public_key).unwrap();

        let contents = std::fs::read_to_string(conf::SECRET_PATH)
            .expect("something went wrong reading the file");
        let secret_pem = contents.trim();
        let secret_key = secret_pem.parse::<SecretKey>().unwrap();
        let public_key = secret_key.public_key();
        assert_eq!(public_key.to_sec1_bytes(), public_key_decode.into());
    }

    #[test]
    fn test_get_address() {
        let myaddress: MyAddress = get_address().unwrap();

        let contents = std::fs::read_to_string(conf::SECRET_PATH)
            .expect("something went wrong reading the file");
        let secret_pem = contents.trim();
        let secret_key = secret_pem.parse::<SigningKey>().unwrap();
        let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
        let signature: Signature = secret_key.sign(message);

        let public_key_decode = hex::decode(myaddress.public_key).unwrap();
        let public_key = p256::PublicKey::from_sec1_bytes(&public_key_decode).expect("import error");
        let verifying_key: VerifyingKey = public_key.into();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }
}