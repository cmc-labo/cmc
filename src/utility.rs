use p256::{SecretKey,};
use qrcode::QrCode;
use image::Luma;
use chrono::{Utc, DateTime};
use serde::{Serialize, Deserialize};
use serde_json::{Value};
use base64::prelude::*;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::{level_filters::LevelFilter, Level};
use std::collections::{HashMap,VecDeque};
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufRead, Write};
use crate::conf;
use crate::crypt;
use crate::kernel;

#[derive(Serialize, Deserialize, Debug)]
struct Ip {
    origin: String,
}

pub fn create_qrcode(address: &String) -> Result<()> {
    let code = QrCode::new(address).unwrap();
    let image = code.render::<Luma<u8>>().build();

    image.save(conf::QRCODE_PATH)?;

    let string = code.render()
        .light_color('　')
        .dark_color('#')
        .build();
    println!("{}", string);
    Ok(())
}

pub fn init_tracing() {
    let utc_datetime: String = Utc::now().format("%Y%m%d%H%M").to_string();
    let log_path = format!("./log/{}.log",utc_datetime);
    let error_log = std::sync::Arc::new(std::fs::File::create(log_path).unwrap());
    // Create a multi-writer that sends output to both file and stdout
    let file_and_stdout = tracing_subscriber::fmt::layer()
        .with_ansi(false) // No ANSI colors in file
        .with_writer(error_log);

    // Create a separate layer for stdout with ANSI colors
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_ansi(true) // Enable colors in terminal
        .with_writer(std::io::stdout);

    // Use registry to combine both layers
    tracing_subscriber::registry()
        .with(LevelFilter::from_level(Level::INFO))
        .with(file_and_stdout)
        .with(stdout_layer)
        .init();
}

#[allow(dead_code)]
pub fn log_output(message: String) {
    let utc_datetime: DateTime<Utc> = Utc::now();
    let t: String = utc_datetime.to_string();
    let filename = format!("./log/{}.txt",&t[0..7]);

    let log_message = format!("[{}] {}", &t[0..19], message);
    println!("{}", log_message);

    if !Path::new(&filename).is_file() {
        let _ = File::create(&filename);
    }
    let mut file_ref = OpenOptions::new()
                        .append(true)
                        .open(filename)
                        .expect("Unable to open file");

    file_ref.write_all(&log_message.as_bytes()).expect("write failed");
    file_ref.write_all(b"\n").expect("write failed");
}

pub async fn get_node_list() -> Result<Vec<kernel::Peer>> {

    let myip = get_myip().await.unwrap();
    let mut node_list: Vec<kernel::Peer> = Vec::new();
    for result in BufReader::new(File::open(conf::PEERS_LIST)?).lines() {
        let line = result?;
        let peer: kernel::Peer = serde_json::from_str(&line).unwrap();
        if peer.ip != myip {
            node_list.push(peer);
        }
    }
    Ok(node_list)
}

pub async fn get_node_list_with_ip() -> Result<Vec<kernel::Peer>> {

    let mut node_list: Vec<kernel::Peer> = Vec::new();
    for result in BufReader::new(File::open(conf::PEERS_LIST)?).lines() {
        let line = result?;
        let peer: kernel::Peer = serde_json::from_str(&line).unwrap();
        node_list.push(peer);
    }
    Ok(node_list)
}

pub async fn get_node_list_exclusion(ip: String) -> Result<Vec<kernel::Peer>> {

    let myip = get_myip().await.unwrap();
    let mut node_list: Vec<kernel::Peer> = Vec::new();
    for result in BufReader::new(File::open(conf::PEERS_LIST)?).lines() {
        let line = result?;
        let peer: kernel::Peer = serde_json::from_str(&line).unwrap();
        if peer.ip != myip && peer.ip != ip {
            node_list.push(peer);
        }
    }
    Ok(node_list)
}

pub async fn get_myip() -> Result<String> {

    let ip: Ip = serde_json::from_str(&reqwest::get("https://httpbin.org/ip")
        .await?
        .text()
        .await?)?;
    Ok(ip.origin)
    // Ok("0.0.0.0".to_string())
}

pub async fn get_price() -> Result<Value> {
    let contents = reqwest::get(conf::CRYPT_RATE_API).await?.text().await?;  
    let res: Value = serde_json::from_str(&contents).unwrap();
    Ok((res["data"]).clone())
}

pub fn balance()-> Result<i32>{

    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();
    let secret_key = secret_pem.parse::<SecretKey>().unwrap();
    let public_key = secret_key.public_key();
    let public_key_serialized = hex::encode(&public_key.to_sec1_bytes());
    let address = crypt::create_address(&public_key); 

    let mut balance: i32 = 0;
    for result in BufReader::new(File::open(conf::BLOCK_PATH)?).lines() {
        let l = result?;
        let param: kernel::Block = serde_json::from_str(&l).unwrap();
        for transaction in param.transactions {
            if transaction.receiver == address {
                balance += transaction.amount;
            } else if transaction.sender == public_key_serialized{
                balance -= transaction.amount; 
            }
        }
    }
    return Ok(balance);
}

pub fn nft_calc(transaction_pool: Vec<kernel::SignedTransaction>) -> HashMap<String, String> {
    let mut nft_holder: HashMap<String, String> = HashMap::new();
    for transaction in transaction_pool {
        if transaction.amount == 0 {
            let transaction_hash = BASE64_STANDARD.encode(serde_json::to_vec(&transaction.clone()).unwrap());
            if transaction.nft_origin == "" && transaction.nft_data != "" && (nft_holder.get(&transaction_hash) == None) {
                nft_holder.insert(transaction_hash, transaction.receiver);
            } else if (nft_holder.get(&transaction.nft_origin) == Some(&transaction.sender)) && transaction.nft_data == "".to_string() { // ここが違う
                println!("{}", transaction.receiver.clone());
                nft_holder.insert(transaction.nft_origin, transaction.receiver); 
            }
        }
    }
    return nft_holder
}

pub async fn get_blocks() -> Result<VecDeque<kernel::Block>> {
    let mut blocks: VecDeque<kernel::Block> = VecDeque::new();
    for result in BufReader::new(File::open(conf::BLOCK_PATH)?).lines() {
        let line: kernel::Block = serde_json::from_str(&result.unwrap()).unwrap();
        blocks.push_front(line);
    }
    Ok(blocks)
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_qrcode() {
        let address = crate::address::get_address().unwrap();
        let _ = create_qrcode(&address.address);
        let path = Path::new(conf::QRCODE_PATH);
        assert!(path.is_file());
    }

    #[test]
    fn test_log_output() {
        let message = "test message".to_string();
        let _ = log_output(message.clone());

        let utc_datetime: DateTime<Utc> = Utc::now();
        let t: String = utc_datetime.to_string();
        let filename = format!("./log/{}.txt",&t[0..7]);

        let f = File::open(filename).unwrap();
        let reader = BufReader::new(f);
        let lines = reader.lines();

        let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
        assert!(input_fn.contains(&message));
    }

    #[tokio::test]
    async fn test_get_node_list() {
        let peers:Vec<kernel::Peer> = get_node_list().await.unwrap();
        assert!(peers[0].ip.parse::<std::net::Ipv4Addr>().is_ok());
    }

    #[tokio::test]
    async fn test_get_price() {
        let data = get_price().await.unwrap();
        let objs: Vec<crate::wallet::Rate> = serde_json::from_value(data).unwrap();
        let rates:Vec<crate::wallet::Rate> = objs.into_iter()
            .filter(|obj| obj.symbol == "BTC" || obj.symbol == "ETH"|| obj.symbol == "SOL"|| obj.symbol == "ADA"|| obj.symbol == "AVAX"|| obj.symbol == "XRP").collect();
        assert_eq!(rates.len(), 6);
    }

    #[test]
    fn test_nft_calc() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let mut transaction_pool: Vec<kernel::SignedTransaction> = Vec::new();
        let transaction1 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(),op_code: "".to_string()};
        let transaction_hash = BASE64_STANDARD.encode(serde_json::to_vec(&crypt::sign_transaction(&transaction1).unwrap()).unwrap());        
        let transaction2 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"bob".to_string(), receiver:"carol".to_string(), amount: 0, nft_data:"".to_string(),nft_origin:transaction_hash,op_code: "".to_string()};
        let transaction3 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data2".to_string(),nft_origin:"".to_string(),op_code: "".to_string()};
        let transaction4 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 1000, nft_data:"".to_string(),nft_origin:"".to_string(),op_code: "".to_string()};

        transaction_pool.push(crypt::sign_transaction(&transaction1).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction2).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction3).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction4).unwrap());
    
        let nft_holder:HashMap<String, String> = nft_calc(transaction_pool);
        for (k, holder) in nft_holder {
            let transaction_str = crypt::base64_decode(&k);
            let transaction:kernel::SignedTransaction = serde_json::from_str(&transaction_str).unwrap();
            if transaction.nft_data == "NFT Data1" {
                assert_eq!(holder, "carol".to_string());
            }
            if transaction.nft_data == "NFT Data2" {
                assert_eq!(holder, "bob".to_string());
            }
        }   
    }

    #[tokio::test]
    async fn test_get_blocks() {
        let mut blocks:VecDeque<kernel::Block> = get_blocks().await.unwrap();
        let genesis: kernel::Block = blocks.pop_back().unwrap();
        assert_eq!("genesisblockhash".to_string(), genesis.hash);
    }
}