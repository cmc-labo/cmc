use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::kernel;

pub static VERSION : &'static str = "0.1.0";
pub static PEERS_LIST : &'static str = "./config/peers.dat";
pub static BLOCK_PATH : &'static str = "./config/blocks.dat";
pub static SECRET_PATH : &'static str = "./config/secret.pem";
pub static QRCODE_PATH : &'static str = "./static/img/qrcode.png";
pub static NFT_TMP_PATH : &'static str = "./static/tmp/";
pub static COINBASE_PUBKEY : &'static str = "coinbase_transaction_pubkey";
pub static SESSION_TOKEN_MAX_AGE: i32 = 900;
pub static TRANSACTION_POOL_MAX: i32 = 1;
pub static MINER_REWARD: i32 = 20;
pub static AIRDROP_AMOUNT: f32 = 10000.0;
pub static AIRDROP_COEFFICIENT: f32 = 0.95;
pub static AIRDROP_DIMINISHING_INTERVAL:i32 = 120;
pub static AIRDROP_BASE_DATE : &'static str = "2025-03-01T00:00:00Z";
pub static DIFFICULTY: usize = 4;
pub static BROADCAST_NODE_NUM: usize = 4;
pub static PORT : &'static str = "3000";

pub static SEED_DNS : &'static str = "MTYwLjE2LjExNy44MA==";
pub static SEED_MINER : &'static str = "MTYwLjE2LjExNy44MA==";

pub static CRYPT_RATE_API : &'static str = "https://api.coincap.io/v2/rates";

pub static POOL: Lazy<Mutex<Vec<kernel::SignedTransaction>>> = Lazy::new(|| Mutex::new(vec![]));