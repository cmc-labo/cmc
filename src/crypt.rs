use p256::{
    ecdsa::{SigningKey, signature::{Signer, Verifier}, Signature, VerifyingKey},
    pkcs8::EncodePrivateKey, PublicKey,};
use pwhash::bcrypt;
use rand_core::{OsRng, RngCore};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use base64::prelude::*;
use ripemd::{Ripemd160};
use anyhow::Result;
use std::{fs::File, io::Write, path::Path};
use crate::conf;
use crate::kernel;

pub fn create_session_token() -> String {
    let mut random = ChaCha8Rng::seed_from_u64(OsRng.next_u64());
    let mut u128_pool = [0u8; 16];
    random.fill_bytes(&mut u128_pool);
    let session_token = u128::from_le_bytes(u128_pool);
    return session_token.to_string();
}

pub fn hash_password(password: &String) -> String {
    bcrypt::hash(password).unwrap()
}

pub fn password_verify(password: &String, hash: &String) -> bool {
    bcrypt::verify(password, hash)
}

pub fn create_secret_key() {
    let path = Path::new(&conf::SECRET_PATH);
    if path.is_file() {
        println!("The private key, public key, and address have already been created.");
    } else {
        let secret_key = SigningKey::random(&mut OsRng);
        let secret_key_serialized = secret_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();
        let mut file = File::create(conf::SECRET_PATH).expect("file not found.");
        writeln!(file, "{}", secret_key_serialized).expect("can not write.");
        println!("created a private key.");
    }
}

pub fn create_address(public_key: &PublicKey) -> String {

    let vk = public_key.to_sec1_bytes();
    let mut hasher = Sha256::new();
    hasher.update(vk);
    let hashed_sha256 = hasher.finalize();

    let mut hasher = Ripemd160::new();
    hasher.update(hashed_sha256);
    let account_id = hasher.finalize();

    let mut payload = account_id.to_vec();
    payload.insert(0, 0x00);

    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let checksum = hasher.finalize();

    payload.append(&mut checksum[0..4].to_vec());

    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let address = base_x::encode(ALPHABET, &payload);

    return address;
}

pub fn sign_transaction(unsignedtransaction: &kernel::UnsignedTransaction) -> Result<kernel::SignedTransaction>{
    let serialized: String = serde_json::to_string(&unsignedtransaction).unwrap();

    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();
    let secret_key = secret_pem.parse::<SigningKey>().unwrap();
    let signature: Signature = secret_key.sign(serialized.as_bytes());
    let signed_transaction = kernel::SignedTransaction {version:unsignedtransaction.version.clone(), time: unsignedtransaction.time.clone(), sender: unsignedtransaction.sender.clone(), receiver: unsignedtransaction.receiver.clone(), amount: unsignedtransaction.amount.clone(), nft_data:unsignedtransaction.nft_data.clone(),nft_origin:unsignedtransaction.nft_origin.clone(), op_code:unsignedtransaction.op_code.clone(),signature: signature.to_string().clone()};

    Ok(signed_transaction)
}

pub async fn verify_signature(signedtransaction: &kernel::SignedTransaction) -> Result<bool>{
    let public_key_decode = hex::decode(&signedtransaction.sender).unwrap();
    if public_key_decode ==  conf::COINBASE_PUBKEY.to_owned().into_bytes() && signedtransaction.amount == conf::MINER_REWARD {
        return Ok(true);
    }
    let public_key = p256::PublicKey::from_sec1_bytes(&public_key_decode)?;
    let verifying_key: VerifyingKey = public_key.into();
    let signature: Signature = signedtransaction.signature.parse::<Signature>().unwrap();
    let req_clone: kernel::SignedTransaction = signedtransaction.clone();
    let posted_transaction = kernel::UnsignedTransaction { version:req_clone.version, time:req_clone.time, sender:req_clone.sender, receiver:req_clone.receiver, amount:req_clone.amount, nft_data: req_clone.nft_data,nft_origin: req_clone.nft_origin, op_code: req_clone.op_code};
    let posted_serialized: String = serde_json::to_string(&posted_transaction).unwrap();
    Ok(verifying_key.verify(posted_serialized.as_bytes(), &signature).is_ok())
}

pub fn base64_str(str: &String) -> String {
    BASE64_STANDARD.encode(&str)
}

fn base64_decode_bytes(b64str: &str) -> Vec<u8> {
    let t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table: [u8; 256] = [0; 256]; 
    for (i, v) in t.as_bytes().iter().enumerate() {
        table[*v as usize] = i as u8; 
    }
    let b64 = String::from(b64str).replace("\r", "").replace("\n", "");
    let b64bytes = b64.as_bytes();
    let mut result: Vec<u8> = vec![];
    let cnt = b64bytes.len() / 4;
    for i in 0..cnt {
        let i0 = b64bytes[i*4+0];
        let i1 = b64bytes[i*4+1];
        let i2 = b64bytes[i*4+2];
        let i3 = b64bytes[i*4+3];
        let c0 = table[i0 as usize] as usize;
        let c1 = table[i1 as usize] as usize;
        let c2 = table[i2 as usize] as usize;
        let c3 = table[i3 as usize] as usize;
        let b24 = (c0 << 18) | (c1 << 12) | (c2 <<  6) | (c3 <<  0);
        let b0 = ((b24 >> 16) & 0xFF) as u8;
        let b1 = ((b24 >>  8) & 0xFF) as u8;
        let b2 = ((b24 >>  0) & 0xFF) as u8;
        result.push(b0);
        if i2 as char != '=' { result.push(b1); }
        if i3 as char != '=' { result.push(b2); }
    }
    result
}

pub fn base64_decode(b64str: &str) -> String {
    String::from_utf8(base64_decode_bytes(b64str)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use chrono::{Utc, DateTime};
    use crate::address;

    #[test]
    fn test_create_session_token() {
        let token = create_session_token();
        let token_filter = token.clone().chars().filter(|&c| matches!(c, '0' ..= '9')).collect::<String>();
        assert_eq!(token_filter.len(), token.len());
    }

    #[test]
    fn test_hash_password() {
        let password = "fMWrZ8sD8pFg".to_string();
        let password_hash = hash_password(&password);
        assert!(bcrypt::verify(&password, &password_hash));
    }

    #[test]
    fn test_password_verify() {
        let password = "fMWrZ8sD8pFg".to_string();
        let password_hash = "$2b$08$/YNAwps.pRpw1tmyss1Kn.kJN0D2pJZgmpDdG4LU68XYURDYse/5O".to_string();
        assert!(password_verify(&password, &password_hash));
    }

    #[test]
    fn test_create_address() {
        let contents = std::fs::read_to_string(conf::SECRET_PATH)
            .expect("something went wrong reading the file");
        let secret_pem = contents.trim();
        let secret_key = secret_pem.parse::<SecretKey>().unwrap();
        let public_key = secret_key.public_key();
        let address = create_address(&public_key);
        assert_eq!(address.len(), 34);
        assert_eq!(address[..1], "1".to_string());
    }

    #[test]
    fn test_sign_transaction() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let my_public_key = address::get_public_key().unwrap();
        let unsigned_transaction = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:my_public_key, receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let signed_transaction = sign_transaction(&unsigned_transaction).unwrap();
        let serialized: String = serde_json::to_string(&unsigned_transaction).unwrap();

        let public_key_decode = hex::decode(&signed_transaction.sender).unwrap();
        let public_key = p256::PublicKey::from_sec1_bytes(&public_key_decode).expect("error");
        let verifying_key: VerifyingKey = public_key.into();
        let signature: Signature = signed_transaction.signature.parse::<Signature>().unwrap();
        assert!(verifying_key.verify(serialized.as_bytes(), &signature).is_ok());
    }

    #[tokio::test]
    async fn test_verify_signature() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let my_public_key = address::get_public_key().unwrap();
        let unsigned_transaction1 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:my_public_key, receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let signed_transaction1 = sign_transaction(&unsigned_transaction1).unwrap();
        assert_eq!(verify_signature(&signed_transaction1).await.unwrap(), true);

        let unsigned_transaction2 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"686F6765686F6765".to_string(), receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let signed_transaction2 = sign_transaction(&unsigned_transaction2).unwrap();
        let result = verify_signature(&signed_transaction2).await;
        assert!(result.is_err());

        let coinbase_pubkey = hex::encode(conf::COINBASE_PUBKEY);
        let unsigned_transaction3 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:coinbase_pubkey.to_string(), receiver:"bob".to_string(), amount: conf::MINER_REWARD, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let signed_transaction3 = sign_transaction(&unsigned_transaction3).unwrap();
        assert_eq!(verify_signature(&signed_transaction3).await.unwrap(), true);
    }

    #[test]
    fn test_base64_str() {
        let str = "hello world".to_string();
        let result = base64_str(&str);
        assert_eq!("aGVsbG8gd29ybGQ=".to_string(), result);
    }

    #[test]
    fn test_base64_decode() {
        let str = "aGVsbG8gd29ybGQ=".to_string();
        let result = base64_decode(&str);
        assert_eq!("hello world".to_string(), result);
    }
}