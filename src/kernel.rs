use p256::{
    ecdsa::{SigningKey,signature::{Signer},Signature},
};
use chrono::{Utc, DateTime};
use serde::{Serialize, Deserialize};
use rand::prelude::SliceRandom;
use rand::Rng;
use sha2::{Digest, Sha256};
use base64::prelude::*;
use tokio::io::AsyncReadExt;
use dotenv::dotenv;
use anyhow::Result;
use tracing::info;
use rusoto_s3::*;
use std::env;
use std::path::PathBuf;
use std::ops::DerefMut;
use std::io::{Write, BufReader, BufRead};
use std::time;
use std::fs::{File,OpenOptions};
use crate::conf;
use crate::crypt;
use crate::node;
use crate::bloom;
use crate::address;
use crate::utility;
use crate::merkle;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Status {
    ACTIVE,
    INACTIVE,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Peer {
    pub ip: String,
    pub protocol: String,
    pub unixtime: i64,
    pub nodetype: String,
    pub version: String,
    pub status: Status,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnsignedTransaction {
    pub version: String,
    pub time: DateTime<Utc>,
    pub sender: String,
    pub receiver: String,
    pub amount: i32,
    pub nft_data: String,
    pub nft_origin: String,
    pub op_code: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SignedTransaction {
    pub version: String,
    pub time: DateTime<Utc>,
    pub sender: String,
    pub receiver: String,
    pub amount: i32,
    pub nft_data: String,
    pub nft_origin: String,
    pub op_code: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Block {
    pub version: String,
    pub time: DateTime<Utc>,
    pub transactions: Vec<SignedTransaction>,
    pub hash: String,
    pub nonce: String,
    pub merkle: String,
    pub miner: String,
    pub validator: String,
    pub op: String,
}

pub async fn handshake(nodetype: &String)-> Result<()> {

    let address = address::get_address().unwrap();
    let my_ip = utility::get_myip().await.unwrap();

    let imv_message = node::InvMessage{version: conf::VERSION.to_string(), node_type: nodetype.to_string(), timestamp: Utc::now(), sender:my_ip.to_string(), address:address.address.to_string()};
    let imv_message_serialized = serde_json::json!(&imv_message);

    let client = reqwest::Client::new();
    let dns_seed = crypt::base64_decode(conf::SEED_DNS);
    let url = format!("http://{}:{}/handshake", dns_seed, conf::PORT);
    let resp = client.post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&imv_message_serialized)
        .send()
        .await?;
    // println!("{:?}", resp);
    println!("{:?}", resp.text().await.unwrap());
    Ok(())
}

pub async fn verify_node(socket_url: String, inv_message: node::InvMessage, protocol: String) -> Result<(), Box<dyn std::error::Error>> {

    let mut ws = websockets::WebSocket::connect(&socket_url).await?;
    println!("Send me a bloom filter");
    ws.send_text("Send me a bloom filter".to_string()).await?;
    if let websockets::Frame::Text { payload: str_bloomfilter, .. } =  ws.receive().await? {
        info!("WebSocket received bloomfilter: {}", str_bloomfilter.clone());

        let mut filter:[i32;10] = [0,0,0,0,0,0,0,0,0,0];
        for (i,c) in str_bloomfilter.chars().enumerate() {
            filter[i] = (c.to_string()).parse::<i32>().unwrap();
        }

        let mut bf = bloom::BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        bf.set_v(inv_message.clone().address.to_string());

        if filter == bf.filter {
            let _ = append_peer(&inv_message.clone().sender, &protocol.clone(), &inv_message.clone().node_type, &inv_message.clone().version).await.unwrap();
            let _ = broadcast_peers_list(protocol.clone(), inv_message.clone().sender).await.unwrap();
            let _ = broadcast_blocks_list(protocol.clone(), inv_message.clone().sender).await.unwrap();
            let _ = airdrop_transaction(inv_message.clone()).await;
        } else {
            info!("Bloom filter match failed.");
            let error = "Bloom filter match failed.".to_string();
            return Err(error.into());
        }
    }
    ws.close(None).await?;
    Ok(())
}

pub async fn append_peer(ip: &String, protocol: &String, nodetype: &String, version: &String)-> Result<()> {
    let utc_datetime: DateTime<Utc> = Utc::now();

    let peer = Peer {ip: ip.to_string(), unixtime: utc_datetime.timestamp(), protocol: protocol.to_string(), nodetype: nodetype.to_string(), version: version.to_string(), status: Status::ACTIVE};
    let str = format!("{:?}", peer);
    info!("{}", str);

    let serialized: Vec<u8> = serde_json::to_vec(&peer).unwrap();
    let mut file_ref = OpenOptions::new()
                        .append(true)
                        .open(conf::PEERS_LIST)
                        .expect("Unable to open file");
    file_ref.write_all(&serialized).expect("write failed");
    file_ref.write_all(b"\n").expect("write failed");
    Ok(())
}

async fn broadcast_peers_list(protocol: String, ip: String) -> Result<()> {
    let mut node_list: Vec<Peer> = Vec::new();
    for result in BufReader::new(File::open(conf::PEERS_LIST)?).lines() {
        let line = result?;
        let peer: Peer = serde_json::from_str(&line).unwrap();
        node_list.push(peer);
    }

    let node_list_serialized = serde_json::json!(&node_list);

    let mut post_url = format!("http://{}:{}/fetch_peers", ip, conf::PORT);
    if protocol == "ipv6".to_string() {
        post_url = format!("http://[{}]:{}/fetch_peers", ip, conf::PORT);
    }
    let client = reqwest::Client::new();
    let resp = client.post(post_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&node_list_serialized)
        .send()
        .await?;
    // println!("{:?}", resp);
    println!("{}", resp.text().await.unwrap());
    Ok(())
}

async fn broadcast_blocks_list(protocol: String, ip: String) -> Result<()> {
    let mut blocks_list: Vec<Block> = Vec::new();
    for result in BufReader::new(File::open(conf::BLOCK_PATH)?).lines() {
        let line = result?;
        let block: Block = serde_json::from_str(&line).unwrap();
        blocks_list.push(block);
    }

    let blocks_list_serialized = serde_json::json!(&blocks_list);

    let mut post_url = format!("http://{}:{}/fetch_blocks", ip, conf::PORT);
    if protocol == "ipv6".to_string() {
        post_url = format!("http://[{}]:{}/fetch_blocks", ip, conf::PORT);
    }
    let client = reqwest::Client::new();
    let resp = client.post(post_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&blocks_list_serialized)
        .send()
        .await?;
    // println!("{:?}", resp);
    println!("{}", resp.text().await.unwrap());
    Ok(())
}

pub async fn transaction(receiver: &String, amount: &i32, nft_data: &String, nft_origin: &String) {
    let unsigned_transaction = UnsignedTransaction {version: conf::VERSION.to_string(), time: Utc::now(), sender:address::get_public_key().unwrap(), receiver:receiver.to_string(), amount: *amount as i32, nft_data:nft_data.to_string(),nft_origin:nft_origin.to_string(), op_code:"".to_string()};
    let signed_transaction = crypt::sign_transaction(&unsigned_transaction).unwrap();
    println!("{:?}", signed_transaction);
    conf::POOL.lock().unwrap().push(signed_transaction.clone());
    if applicable_miner().await.unwrap() {
        if conf::POOL.lock().unwrap().len() > conf::TRANSACTION_POOL_MAX.try_into().unwrap() {
            let _ = make_block().await;               
        }
    }
    let ip = "0.0.0.0".to_string();
    let _ = transaction_broadcaset(signed_transaction.clone(), ip).await;
}

async fn airdrop_transaction(inv_message: node::InvMessage) {
    let amount = airdrop_calc().await;
    let unsigned_transaction = UnsignedTransaction {version: conf::VERSION.to_string(), time: Utc::now(), sender:address::get_public_key().unwrap(), receiver:inv_message.clone().address.to_string(), amount: amount, nft_data:"".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
    let signed_transaction = crypt::sign_transaction(&unsigned_transaction).unwrap();
    conf::POOL.lock().unwrap().push(signed_transaction.clone());
    let ip = "0.0.0.0".to_string();
    let _ = transaction_broadcaset(signed_transaction, ip).await;
}

async fn airdrop_calc() -> i32 {
    let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339(conf::AIRDROP_BASE_DATE).unwrap().into();
    let utc_datetime_now: DateTime<Utc> = Utc::now();
    let elapsed_days: i32 = ((utc_datetime_now.timestamp() - utc_datetime.timestamp()) / 86400).try_into().unwrap();
    let x = elapsed_days / conf::AIRDROP_DIMINISHING_INTERVAL;
    let result = conf::AIRDROP_AMOUNT as f32 * conf::AIRDROP_COEFFICIENT.powf(x as f32);
    if result < 1000.0 {
        return 1000;
    }
    return result.round() as i32;
}

pub async fn transaction_broadcaset(signed_transaction: SignedTransaction, sender_ip: String)-> Result<()> {
    let signed_serialized = serde_json::json!(&signed_transaction);

    let mut node_list: Vec<Peer> = utility::get_node_list_exclusion(sender_ip).await?;
    println!("{:?}", node_list.clone());
    if node_list.clone().len() == 0 {
        return Ok(())
    } else if node_list.clone().len() > conf::BROADCAST_NODE_NUM {
        let mut rng = rand::thread_rng();
        node_list.shuffle(&mut rng);
        println!("{:?}", &node_list.clone());
        node_list = (&node_list[..conf::BROADCAST_NODE_NUM]).to_vec();
    }
    
    for node in node_list.clone() {
        if node.status == Status::ACTIVE {
            let mut ip = node.clone().ip;
            if node.protocol == "ipv6" {
                ip = format!("[{}]", node.ip);
            }
            let heatlth_url = format!("http://{}:{}/health", ip, conf::PORT);
            let post_url = format!("http://{}:{}/transaction_pool", ip, conf::PORT);

            let result = reqwest::get(heatlth_url.clone()).await;
            match result {
                Err(_error) => {
                    println!("transaction broadcast error, {}", heatlth_url.clone());
                }
                Ok(_) =>  {
                    let client = reqwest::Client::new();
                    let resp = client.post(post_url)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .json(&signed_serialized)
                        .send()
                        .await?;
                    // println!("{:?}", resp);
                    println!("{}", resp.text().await.unwrap());
                }
            }
        }
    }
    Ok(())
}

pub async fn check_node_list(ip: &String) -> bool {
    let node_list: Vec<Peer> = utility::get_node_list_with_ip().await.unwrap();
    for node in node_list {
        if node.ip == *ip {
            return true;
        }
    }
    return false
}

pub async fn applicable_miner() -> Result<bool> {
    let f = File::open(conf::BLOCK_PATH).unwrap();
    let reader = BufReader::new(f);
    let lines = reader.lines();
    let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
    let param:Block = serde_json::from_str(&input_fn).unwrap();
    let miner = crypt::base64_decode(&param.miner);

    let myip = utility::get_myip().await.unwrap();
    if miner == myip {
        return Ok(true);
    }
    Ok(false)
}

pub async fn make_block()-> Result<()> {
    let new_block:Block  = proof_of_work().await.unwrap();
    let _ = broadcast_new_block(new_block.clone()).await.unwrap();

    // let _ = miner_reward();
    Ok(())
}

async fn proof_of_work() -> Result<Block>{
    let f = File::open(conf::BLOCK_PATH).unwrap();
    let reader = BufReader::new(f);
    let lines = reader.lines();
    let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
    let param:Block = serde_json::from_str(&input_fn).unwrap();

    // proof of work
    let now = time::Instant::now();
    let previous_hash = param.hash;
    let mut num = rand::thread_rng().gen_range(0..1000000);
    let mut hash_num = format!("{}{}", previous_hash, num.to_string());
    let mut header = Sha256::digest(hash_num);
    let mut target: String  = (&hex::encode(header)[..conf::DIFFICULTY]).to_string();

    let mut cnt = 1;
    println!("count: {} {:x}", cnt, header);

    let str: String = "0".to_string();
    let difficulty_str = str.repeat(conf::DIFFICULTY.try_into().unwrap());

    while target != difficulty_str {
        println!("count: {} {:x}", cnt, header);
        num = rand::thread_rng().gen_range(0..1000000);
        hash_num = format!("{}{}", previous_hash, num.to_string());
        header = Sha256::digest(hash_num);
        target = (&hex::encode(header)[..conf::DIFFICULTY]).to_string();
        cnt += 1;
    }

    info!("Proof of work count: {} {:x}", cnt, header);
    println!("{:?}, difficulty is {}", now.elapsed(), conf::DIFFICULTY);

    // create merkle root (Since we use binding.deref_mut, we have put it out as a separate function)
    let merkle_root = generate_merkle_tree().await;

    // transactions (Since we use binding.deref_mut, we have put it out as a separate function)
    let objs = get_transactions().await;

    // Pos
    let peers = utility::get_node_list().await.unwrap();
    let mut candidates: Vec<Peer> = Vec::new();
    for peer in peers {
        if peer.nodetype == "c".to_string() && peer.status == Status::ACTIVE {
            candidates.push(peer);
        }
    } 
    let mut miner : String = conf::SEED_MINER.to_string();
    let mut validator : String = conf::SEED_MINER.to_string();
    if candidates.len() > 2 {
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        miner = BASE64_STANDARD.encode(&candidates[0].clone().ip);
        validator = BASE64_STANDARD.encode(&candidates[1].clone().ip);
    }
    info!("Miner: {}, Validator: {}", miner, validator);

    // wallet address for reward receiving
    let address = address::get_address().unwrap();

    // make new block
    let new_block = Block{version: conf::VERSION.to_string(), time: Utc::now(), transactions: objs.to_vec(), hash: hex::encode(header).to_string(), nonce: num.to_string(), merkle: merkle_root, miner: miner.to_string(), validator: validator.to_string(), op: address.address.to_string()};
    println!("{:?}", new_block);
    Ok(new_block)
}

async fn generate_merkle_tree() -> String {
    let mut binding = conf::POOL.lock().unwrap();
    let objs = binding.deref_mut();

    let mut signatures:Vec<String> = Vec::new();
    for obj in objs.clone() {
        signatures.push(obj.signature)
    }
    let merkle_root = merkle::merkle_root(signatures);
    info!("Merkle Root: {}", merkle_root);
    return merkle_root
}

async fn get_transactions() -> Vec<SignedTransaction> {
    let mut binding = conf::POOL.lock().unwrap();
    let objs = binding.deref_mut();

    let mut transactions:Vec<SignedTransaction> = Vec::new();
    for obj in objs.clone() {
        transactions.push(obj)
    }
    return transactions
}

pub async fn broadcast_new_block(new_block: Block) -> Result<()> {
    let block_serialized = serde_json::json!(&new_block);

    let f = File::open(conf::BLOCK_PATH).unwrap();
    let reader = BufReader::new(f);
    let lines = reader.lines();
    let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
    let param:Block = serde_json::from_str(&input_fn).unwrap();
    let validator = crypt::base64_decode(&param.validator);

    let mut health_url = format!("http://{}:{}/health", validator, conf::PORT);
    let mut validation_url = format!("http://{}:{}/block_validate", validator, conf::PORT);

    for result in BufReader::new(File::open(conf::PEERS_LIST).unwrap()).lines() {
        let line = result?;
        let peer: Peer = serde_json::from_str(&line).unwrap();
        if peer.ip == validator {
            if peer.protocol == "ipv6".to_string() {
                health_url = format!("http://[{}]:{}/health", validator, conf::PORT);
                validation_url = format!("http://[{}]:{}/block_validate", validator, conf::PORT);
            }
        }
    }

    let result = reqwest::get(health_url.clone()).await;
    match result {
        Err(_error) => {
            let dns_seed = crypt::base64_decode(conf::SEED_DNS);
            validation_url = format!("http://{}:{}/block_validate", dns_seed, conf::PORT);
            let client = reqwest::Client::new();
            let resp = client.post(validation_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&block_serialized)
                .send()
                .await?;
            // println!("{:?}", resp);
            println!("{}", resp.text().await.unwrap());
        }
        Ok(_) =>  {
            let client = reqwest::Client::new();
            let resp = client.post(validation_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&block_serialized)
                .send()
                .await?;
            // println!("{:?}", resp);
            println!("{}", resp.text().await.unwrap());
        }
    }
    Ok(())
}

pub async fn genesis_check()-> Result<bool> {
    for result in BufReader::new(File::open(conf::BLOCK_PATH)?).lines() {
        let l = result?;
        let param:Block = serde_json::from_str(&l).unwrap();
        if param.hash == "genesisblockhash" {
            info!("The genesis block hash is normal.");
            return Ok(true);
        }
        break;
    }
    Ok(false)
}

pub async fn pow_check(new_block: Block)-> Result<bool> {

    let f = File::open(conf::BLOCK_PATH).unwrap();
    let reader = BufReader::new(f);
    let lines = reader.lines();
    let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
    let param:Block = serde_json::from_str(&input_fn).unwrap();

    let previous_hash = param.hash;

    let nonce = new_block.nonce;
    let hash_num = format!("{}{}", previous_hash, nonce.to_string());
    let header = Sha256::digest(hash_num);
    if hex::encode(header) != new_block.hash {
        info!("Mining is fraudulent.");
        return Ok(false);
    } 
    info!("Mining hash check has passed.");
    return Ok(true);
}

pub async fn block_override(new_block: Block) -> Result<bool> {

    let f = File::open(conf::BLOCK_PATH).unwrap();
    let reader = BufReader::new(f);
    let lines = reader.lines();
    let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
    let last_block:Block = serde_json::from_str(&input_fn).unwrap();

    if last_block == new_block {
        info!("New Block request, but the block has already been imported.");
        return Ok(false);
    }
    let serialized: Vec<u8> = serde_json::to_vec(&new_block).unwrap();
    let mut file_ref = OpenOptions::new()
                        .append(true)
                        .open(conf::BLOCK_PATH)
                        .expect("Unable to open file");

    file_ref.write_all(&serialized).expect("write failed");
    file_ref.write_all(b"\n").expect("write failed");
    info!("New Block have been generated.");
    Ok(true)
}

pub async fn create_coinbase_transaction(new_block: Block) -> Result<SignedTransaction> {
    let unsignedtransaction = UnsignedTransaction {version: conf::VERSION.to_string(), time:Utc::now(), sender: hex::encode(conf::COINBASE_PUBKEY).to_string(), receiver: new_block.op, amount: conf::MINER_REWARD, nft_data:"".to_string(),nft_origin:"".to_string(), op_code:"".to_string()};
    let serialized: String = serde_json::to_string(&unsignedtransaction).unwrap();
    let contents = std::fs::read_to_string(conf::SECRET_PATH)
        .expect("something went wrong reading the file");
    let secret_pem = contents.trim();
    let secret_key = secret_pem.parse::<SigningKey>().unwrap();
    let sig1: Signature = secret_key.sign(serialized.as_bytes());
    let signed_transaction = SignedTransaction {version: conf::VERSION.to_string(), time: unsignedtransaction.time, sender: unsignedtransaction.sender, receiver: unsignedtransaction.receiver, amount: unsignedtransaction.amount, signature: sig1.to_string(), nft_data:"".to_string(),nft_origin:"".to_string(), op_code:"".to_string()};
    Ok(signed_transaction)
}


pub async fn block_broadcast(block: Block)-> Result<()> {
    let miner_ip = crypt::base64_decode(&block.clone().miner);
    let block_serialized = serde_json::json!(&block);

    let mut node_list: Vec<Peer> = utility::get_node_list().await?;
    let miner = node_list.clone().into_iter().find(|x|*x.ip == miner_ip);
    if miner == None {
        let seed_dns = crypt::base64_decode(conf::SEED_DNS);
        let post_url = format!("http://{}:{}/block_update", seed_dns, conf::PORT);
        let client = reqwest::Client::new();
        let resp = client.post(post_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&block_serialized)
            .send()
            .await?;
        // println!("{:?}", resp);
        println!("{}", resp.text().await.unwrap());
    }

    if node_list.len() == 0 {
        return Ok(())
    } else if node_list.len() > conf::BROADCAST_NODE_NUM {
        let mut rng = rand::thread_rng();
        node_list.shuffle(&mut rng);
        println!("{:?}", &node_list);
        node_list = (&node_list[..conf::BROADCAST_NODE_NUM]).to_vec();
        if !node_list.contains(&miner.clone().unwrap()) {
            node_list.push(miner.unwrap());
        }
    }

    for node in node_list {
        if node.status == Status::ACTIVE {
            let mut ip = node.clone().ip;
            if node.protocol == "ipv6" {
                ip = format!("[{}]", node.ip);
            }
            let heatlth_url = format!("http://{}:{}/health", ip, conf::PORT);
            let post_url = format!("http://{}:{}/block_update", ip, conf::PORT);

            let result = reqwest::get(heatlth_url.clone()).await;
            match result {
                Err(_error) => {
                    println!("error, {}", heatlth_url.clone());
                }
                Ok(_) =>  {
                    let client = reqwest::Client::new();
                    let resp = client.post(post_url)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .json(&block_serialized)
                        .send()
                        .await?;
                    // println!("{:?}", resp);
                    println!("{}", resp.text().await.unwrap());
                }
            }
        }
    }
    Ok(())
}

pub async fn coinbase_broadcast(signed_transaction: SignedTransaction, block: Block)-> Result<()> {
 
     // Clear the transaction pool 
    conf::POOL.lock().unwrap().clear();
 
    let signed_serialized = serde_json::json!(&signed_transaction);
    let miner_ip = crypt::base64_decode(&block.clone().miner);

    let mut node_list: Vec<Peer> = utility::get_node_list().await?;
    let miner = node_list.clone().into_iter().find(|x|*x.ip == miner_ip);
    if miner == None {
        let seed_dns = crypt::base64_decode(conf::SEED_DNS);
        let post_url = format!("http://{}:{}/transaction_pool", seed_dns, conf::PORT);
        let client = reqwest::Client::new();
        let resp = client.post(post_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&signed_serialized)
            .send()
            .await?;
        // println!("{:?}", resp);
        println!("{}", resp.text().await.unwrap());
        return Ok(())
    }

    if node_list.len() == 0 {
        return Ok(())
    } else if node_list.len() > conf::BROADCAST_NODE_NUM {
        let mut rng = rand::thread_rng();
        node_list.shuffle(&mut rng);
        println!("{:?}", &node_list);
        node_list = (&node_list[..conf::BROADCAST_NODE_NUM]).to_vec();
        if !node_list.contains(&miner.clone().unwrap()) {
            node_list.push(miner.unwrap());
        }
    }
    
    for node in node_list {
        if node.status == Status::ACTIVE {
            let mut ip = node.clone().ip;
            if node.protocol == "ipv6" {
                ip = format!("[{}]", node.ip);
            }
            let heatlth_url = format!("http://{}:{}/health", ip, conf::PORT);
            let post_url = format!("http://{}:{}/transaction_pool", ip, conf::PORT);

            let result = reqwest::get(heatlth_url.clone()).await;
            match result {
                Err(_error) => {
                    println!("error, {}", heatlth_url.clone());
                }
                Ok(_) =>  {
                    let client = reqwest::Client::new();
                    let resp = client.post(post_url)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .json(&signed_serialized)
                        .send()
                        .await?;
                    // println!("{:?}", resp);
                    println!("{}", resp.text().await.unwrap());
                }
            }
        }
    }
    Ok(())
}

pub async fn processing_mutex_vector(block: Block) -> Vec<SignedTransaction>{
    let mut binding = conf::POOL.lock().unwrap();
    let objs = binding.deref_mut();

    for transaction in block.transactions {
        if let Some(remove_index) = objs.iter().position(|x| *x == transaction){
            objs.remove(remove_index);
        }
    }
    return objs.to_vec();
}

pub async fn upload_nft_to_ipfs(nft_tmp_path: String) -> Result<String> {

    let pathbuf = PathBuf::from(nft_tmp_path.clone());
    let ext_string = pathbuf
        .extension()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let time = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let file_key = format!("{}.{}", time, ext_string);

    let _ = dotenv();
    let aws_access_key = env::var("AWS_ACCESS_KEY_ID").unwrap();
    let aws_secret_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap();
    let aws_bucket_name = env::var("AWS_BUCKET_NAME").unwrap();
    let aws_region = env::var("AWS_REGION").unwrap();

    std::env::set_var("AWS_ACCESS_KEY_ID", aws_access_key);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", aws_secret_key);

    let s3_client = S3Client::new(aws_region.parse().unwrap());
    let mut file = tokio::fs::File::open(nft_tmp_path.clone()).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let _result = s3_client.put_object(PutObjectRequest {
        bucket: String::from(aws_bucket_name.clone()),
        key: file_key.clone(),
        body: Some(StreamingBody::from(buffer)),
        ..Default::default()
    }).await?;
    
    let ipfs_path = format!("https://{}.s3.{}.amazonaws.com/{}", aws_bucket_name, aws_region, file_key);
    info!("NFT Created! IPFS path: {}", ipfs_path);
    let nft_data = crypt::base64_str(&ipfs_path);
    Ok(nft_data)
}

pub async fn check_aws_credential() -> bool {
    let _ = dotenv();
    let aws_access_key = env::var("AWS_ACCESS_KEY_ID").unwrap();
    let aws_secret_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap();
    let aws_bucket_name = env::var("AWS_BUCKET_NAME").unwrap();
    let aws_region = env::var("AWS_REGION").unwrap();

    if aws_access_key.is_empty() || aws_secret_key.is_empty() || aws_bucket_name.is_empty() || aws_region.is_empty() {
        return false;
    }
    return true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name_of_val;
    use std::fs;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_handshake() {
        let nodetype = "c".to_string();
        let address = "1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string();
        let my_ip = "0.0.0.0".to_string();

        let imv_message = node::InvMessage{version: "1.0.0".to_string(), node_type: nodetype.to_string(), timestamp: Utc::now(), sender:my_ip.to_string(), address: address.clone().to_string()};
        let imv_message_serialized = serde_json::json!(&imv_message);

        let param: node::InvMessage= serde_json::from_value(imv_message_serialized).unwrap();
        assert_eq!(param.address, address);       
    }

    #[test]
    fn test_transaction() {
        let receiver = "1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string();
        let amount = 2000;
        let nft_data = "".to_string();
        let nft_origin = "".to_string();
        let unsigned_transaction = UnsignedTransaction {version: conf::VERSION.to_string(), time: Utc::now(), sender:address::get_public_key().unwrap(), receiver:receiver.to_string(), amount: amount, nft_data:nft_data.to_string(),nft_origin:nft_origin.to_string(), op_code:"".to_string()};
        let signed_transaction = crypt::sign_transaction(&unsigned_transaction).unwrap();
        assert_eq!(signed_transaction.receiver, receiver);
        assert_eq!(signed_transaction.amount, amount);
    }

    #[tokio::test]
    async fn test_transaction_broadcaset_nodelist() {
        let mut node_list: Vec<String> = vec!["192.168.33.10".to_string(), "192.168.33.11".to_string(), "192.168.33.12".to_string(), "192.168.33.13".to_string(), "192.168.33.14".to_string(), "192.168.33.15".to_string()];
        if node_list.len() == 0 {
            //
        } else if node_list.len() > 5 {
            let mut rng = rand::thread_rng();
            node_list.shuffle(&mut rng);
            node_list = (&node_list[..4]).to_vec();
        }
        assert_eq!(node_list.len(), 4);
    }

    #[tokio::test]
    async fn test_check_aws_credential() {
        let aws_credential = check_aws_credential().await;
        assert!(type_name_of_val(&aws_credential).contains("bool"));
    }

    #[tokio::test]
    async fn test_upload_nft_to_ipfs() {
        let file_name = "foo.txt";
        let nft_tmp_path = format!("./static/tmp/{}", file_name);
        let mut file = File::create(nft_tmp_path.clone()).unwrap();
        file.write_all(b"Hello, world!").unwrap();
        let result = upload_nft_to_ipfs(nft_tmp_path.clone()).await.unwrap();
        let nft_data = crypt::base64_decode(&result);

        let resp = reqwest::get(nft_data).await.expect("request failed");
        let body = resp.text().await.expect("body invalid");
        assert_eq!(body, "Hello, world!");

        fs::remove_file(nft_tmp_path).unwrap();
    }

    #[tokio::test]
    async fn test_check_node_list() {
        let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 999, 999, 999)), 8080);
        let result = check_node_list(&socket.ip().to_string()).await;
        assert_eq!(result, false);
    }

    #[tokio::test]
    async fn test_transaction_broadcaset() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let signed_transaction = SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: "029e1baf299".to_string(),
            receiver: "1E5b59jN4".to_string(),
            amount: 2000,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "eyJ0aW1lIjoiMjAyNS0w".to_string(),
        };
        let signed_serialized = serde_json::json!(&signed_transaction);
        let peer1 = Peer {ip: "192.168.33.10".to_string(), protocol: "ipv4".to_string(), unixtime: 1740009605, nodetype: "c".to_string(), version: "1.0.1".to_string(), status:Status::ACTIVE };
        let peer2 = Peer {ip: "::ffff:c0a8:210a".to_string(), protocol: "ipv6".to_string(), unixtime: 1740009605, nodetype: "c".to_string(), version: "1.0.1".to_string(), status:Status::ACTIVE };

        let mut node_list :Vec<Peer> = Vec::new();
        node_list.push(peer1);
        node_list.push(peer2);
        println!("{:?}", node_list);

        for node in node_list {
            if node.status == Status::ACTIVE {
                let mut ip = node.clone().ip;
                if node.protocol == "ipv6" {
                    ip = format!("[{}]", node.ip);
                }
                let health_url = format!("http://{}:{}/health", ip, conf::PORT);
                let post_url = format!("http://{}:{}/transaction_pool", ip, conf::PORT);

                if node.ip == "192.168.33.10" {
                    assert_eq!(health_url, "http://192.168.33.10:3000/health".to_string());
                } else if node.ip == "::ffff:c0a8:210a".to_string() {
                    assert_eq!(health_url, "http://[::ffff:c0a8:210a]:3000/health".to_string());
                }

                let result = reqwest::get(health_url.clone()).await;
                match result {
                    Err(_error) => {
                        println!("error, {}", health_url.clone());
                    }
                    Ok(_) => {
                        let client = reqwest::Client::new();
                        let resp = client.post(post_url)
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .json(&signed_serialized)
                            .send()
                            .await;
                        let body = resp.expect("REASON").text().await.unwrap();   
                        println!("{}", body);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_applicable_miner() {
        let result = applicable_miner().await.unwrap();
        assert!(type_name_of_val(&result).contains("bool"));
    }

    #[tokio::test]
    async fn test_proof_of_work() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let transaction1 = UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data1".to_string(),nft_origin:"".to_string(), op_code:"".to_string()};
        let transaction_hash = BASE64_STANDARD.encode(serde_json::to_vec(&crypt::sign_transaction(&transaction1).unwrap()).unwrap());
        let transaction2 = UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"bob".to_string(), receiver:"carol".to_string(), amount: 0, nft_data:"".to_string(),nft_origin:transaction_hash, op_code:"".to_string()};
        let transaction3 = UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 0, nft_data:"NFT Data2".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let transaction4 = UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bob".to_string(), amount: 1000, nft_data:"".to_string(),nft_origin:"".to_string(), op_code:"".to_string()};

        conf::POOL.lock().unwrap().push(crypt::sign_transaction(&transaction1).unwrap());
        conf::POOL.lock().unwrap().push(crypt::sign_transaction(&transaction2).unwrap());
        conf::POOL.lock().unwrap().push(crypt::sign_transaction(&transaction3).unwrap());
        conf::POOL.lock().unwrap().push(crypt::sign_transaction(&transaction4).unwrap());

        let block = proof_of_work().await.unwrap();
        assert_eq!(block.transactions.len(), 4);
        assert_eq!(block.hash[..conf::DIFFICULTY], "0000".to_string());
    }

    #[tokio::test]
    async fn test_broadcast_new_block() {
        let address = address::get_address().unwrap();
        let new_block = Block {version: "1.0.0".to_string(), time: Utc::now(), transactions: [].to_vec(), hash: "0000bdebe741af3994f4a2160b4480a23ca137aaf0ac51b10fe574f04afc7be4".to_string(), nonce: "70736".to_string(), merkle: "34ECB4DF98".to_string(), miner:"MTkyLjE2OC4zMy4xMA==".to_string(), validator:"MTkyLjE2OC4zMy4xMA==".to_string(), op:address.address.to_string()};
        let block_serialized = serde_json::json!(&new_block);
        let client = reqwest::Client::new();
        let resp = client.post("http://httpbin.org/post")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&block_serialized)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().is_success(), true);
    }

    #[tokio::test]
    async fn test_genesis_check() {
        let result = genesis_check().await.unwrap();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn test_pow_check() {
        let address = address::get_address().unwrap();
        let new_block = Block {version: "1.0.0".to_string(), time: Utc::now(), transactions: [].to_vec(), hash: "0000bdebe741af3994f4a2160b4480a23ca137aaf0ac51b10fe574f04afc7be4".to_string(), nonce: "00000".to_string(), merkle: "34ECB4DF98".to_string(), miner:"MTkyLjE2OC4zMy4xMA==".to_string(), validator:"MTkyLjE2OC4zMy4xMA==".to_string(), op:address.address.to_string()};
        let result = pow_check(new_block).await.unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_block_override() {
        let address = address::get_address().unwrap();
        let new_block = Block {version: "1.0.0".to_string(), time: Utc::now(), transactions: [].to_vec(), hash: "0000bdebe741af3994f4a2160b4480a23ca137aaf0ac51b10fe574f04afc7be4".to_string(), nonce: "00000".to_string(), merkle: "34ECB4DF98".to_string(), miner:"MTkyLjE2OC4zMy4xMA==".to_string(), validator:"MTkyLjE2OC4zMy4xMA==".to_string(), op:address.address.to_string()};
        let tmp_path = "./static/tmp/tmp_block_override_test.txt".to_string();

        // file create
        let mut file = File::create(tmp_path.clone()).unwrap();
        let _ = file.write_all(String::from("hello world!\n").as_bytes());

        // override file with new block
        let serialized: Vec<u8> = serde_json::to_vec(&new_block).unwrap();
        let mut file_ref = OpenOptions::new()
                            .append(true)
                            .open(tmp_path.clone())
                            .expect("Unable to open file");

        file_ref.write_all(&serialized).expect("write failed");
        file_ref.write_all(b"\n").expect("write failed");

        // test block override fn
        let f = File::open(tmp_path.clone()).unwrap();
        let reader = BufReader::new(f);
        let lines = reader.lines();
        let input_fn = lines.last().unwrap_or(Ok("".to_string())).unwrap();
        let param:Block = serde_json::from_str(&input_fn).unwrap();
        assert_eq!(param.version, "1.0.0".to_string());
        assert_eq!(param, new_block);

        let _ = std::fs::remove_file(tmp_path);
    }

    #[tokio::test]
    async fn test_create_coinbase_transaction() {
        let address = address::get_address().unwrap();
        let new_block = Block {version: "1.0.0".to_string(), time: Utc::now(), transactions: [].to_vec(), hash: "0000bdebe741af3994f4a2160b4480a23ca137aaf0ac51b10fe574f04afc7be4".to_string(), nonce: "00000".to_string(), merkle: "34ECB4DF98".to_string(), miner:"MTkyLjE2OC4zMy4xMA==".to_string(), validator:"MTkyLjE2OC4zMy4xMA==".to_string(), op:address.address.to_string()};
        let coinbase_transaction = create_coinbase_transaction(new_block).await.unwrap();
        assert_eq!(crypt::verify_signature(&coinbase_transaction).await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_processing_mutex_vector() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let signed_transaction1 = SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "alice".to_string(), receiver:"C229797C82F9D5".to_string(), amount: 10, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(), op_code:"".to_string()};
        let signed_transaction2 = SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "bob".to_string(), receiver:"ca55d5746f0e1b".to_string(), amount: 5, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(), op_code:"".to_string()};
        let signed_transaction3 = SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "carol".to_string(), receiver:"2CEDE67EB49A01DC".to_string(), amount: 15, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(), op_code:"".to_string()};
        let signed_transaction4 = SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "alice".to_string(), receiver:"2CEDE67EB49A01DC".to_string(), amount: 40, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(), op_code:"".to_string()};
        conf::POOL.lock().unwrap().push(signed_transaction1.clone());
        conf::POOL.lock().unwrap().push(signed_transaction2.clone());
        conf::POOL.lock().unwrap().push(signed_transaction3.clone());
        conf::POOL.lock().unwrap().push(signed_transaction4.clone());
        // println!("{:?}", conf::POOL.lock().unwrap());

        let mut transactions: Vec<SignedTransaction> = Vec::new();
        transactions.push(signed_transaction1);
        transactions.push(signed_transaction2);
        let block = Block {version:"".to_string(), time: utc_datetime, transactions: transactions, hash: "".to_string(), nonce: "".to_string(), merkle: "".to_string(), miner:"".to_string(), validator: "".to_string(), op: "".to_string()};

        let objs = processing_mutex_vector(block).await;
        conf::POOL.lock().unwrap().clear();
        for obj in objs {
            conf::POOL.lock().unwrap().push(obj);
        }
        assert_eq!(conf::POOL.lock().unwrap().len(), 2);
        conf::POOL.lock().unwrap().clear();
    }

    #[tokio::test]
    async fn test_unixtime_day() {
        let utc_datetime1: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z").unwrap().into();
        let utc_datetime2: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-02T00:00:00Z").unwrap().into();
        assert_eq!(utc_datetime2.timestamp() - utc_datetime1.timestamp(), 86400);
    }

    #[tokio::test]
    async fn airdrop_calc() {
        let base_date = "2025-01-01T00:00:00Z".to_string();
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339(&base_date).unwrap().into();
        let target_date = "2026-02-01T00:00:00Z".to_string();
        let utc_datetime2: DateTime<Utc> = DateTime::parse_from_rfc3339(&target_date).unwrap().into();
        // let utc_datetime2: DateTime<Utc> = Utc::now();
        let elapsed_days: i32 = ((utc_datetime2.timestamp() - utc_datetime.timestamp()) / 86400).try_into().unwrap();

        let amount: f32 = 10000.0;
        let coefficient: f32 = 0.95;
        let diminishing_interval_days:i32 = 120;
        let x = elapsed_days / diminishing_interval_days;
        let result = amount as f32 * coefficient.powf(x as f32);
        assert_eq!(result.round() as i32, 8574);
    }
}