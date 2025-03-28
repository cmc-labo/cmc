use axum::{
    extract, extract::WebSocketUpgrade, extract::ws::{WebSocket},
    response::{Response,IntoResponse},
    extract::ConnectInfo, http::{StatusCode},
};
use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use tracing::info;
use std::fs::{File};
use std::io::{Write};
use std::net::SocketAddr;
use std::ops::DerefMut;
use crate::kernel;
use crate::utility;
use crate::crypt;
use crate::conf;
use crate::address;
use crate::bloom;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InvMessage {
    pub version: String,
    pub node_type: String, 
    pub timestamp: DateTime<Utc>,
    pub sender: String,
    pub address: String,
}

pub async fn handle_transaction_pool(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(signed_transaction): extract::Json<kernel::SignedTransaction>) -> Response {
    // log request_ip
    info!("Transaction Request: {}", &addr.clone());

    // check request_ip in node_list
    if !kernel::check_node_list(&addr.clone().ip().to_string()).await {
        info!("Requested ip is not registered in node_list");
        return "Your ip is not register in node_list".into_response();
    } else {
        println!("Node check passed");
    }

    // verify transaction_signature
    if !crypt::verify_signature(&signed_transaction).await.unwrap() {
        info!("transaction signature or public key is something wrong");
        return "Your transaction signature or public key is something wrong".into_response();
    }

    // check double transfer
    if !check_double_transfer(signed_transaction.clone()).await {
        info!("Requested transaction is already in transaction pool.");
        return "Requested transaction is already in transaction pool.".into_response();
    } else if !check_double_transfer_in_blocks(signed_transaction.clone()).await{
        info!("Requested transaction is already in blocks.");
        return "Requested transaction is already in blocks.".into_response();
    } else {
    // if there is no dupulicate, push transaction into toransaction_pool
        conf::POOL.lock().unwrap().push(signed_transaction.clone());
        let _ = kernel::transaction_broadcaset(signed_transaction.clone(), addr.clone().ip().to_string()).await;
        if kernel::applicable_miner().await.unwrap() {
            if conf::POOL.lock().unwrap().len() > conf::TRANSACTION_POOL_MAX.try_into().unwrap() {
                let _ = kernel::make_block().await;               
            }
        }
    }
    return "Transaction transfer was successful.".into_response();
}

pub async fn handle_block_validate(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(new_block): extract::Json<kernel::Block>) -> Response {
    // log request_ip
    info!("Block Validation Request: {}", &addr.clone());

    // check request_ip in node_list
    if !kernel::check_node_list(&addr.clone().ip().to_string()).await {
        info!("Requested ip is not registered in node_list");
        return "Your ip is not register in node_list".into_response();
    }

    if !kernel::genesis_check().await.unwrap() {
        info!("genesis hash is something wrong.");
    }

    // Validate Hash Calculation. If validation fails, validator generate the block himself.
    if !kernel::pow_check(new_block.clone()).await.unwrap() {
        let _ = kernel::make_block().await;
        return "There was an error in the hash calculation.".into_response();
    }

    // bolock override
    let _ = kernel::block_override(new_block.clone()).await.unwrap();

    // create coinbase transaction
    let coinbase_transaction = kernel::create_coinbase_transaction(new_block.clone()).await.unwrap();

    // block broadcast
    let _ = kernel::block_broadcast(new_block.clone()).await.unwrap();

    // coinbase transaction broadcast
    let _ = kernel::coinbase_broadcast(coinbase_transaction, new_block.clone()).await.unwrap();

    return "A Block validation was successful.".into_response();
}

pub async fn handle_block_update(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(block): extract::Json<kernel::Block>) -> Response {
    // log request_ip
    info!("Block Update Request: {}", &addr.clone());

    // check request_ip in node_list
    if !kernel::check_node_list(&addr.clone().ip().to_string()).await {
        info!("Requested ip is not register in node_list.");
        return "Your ip is not register in node_list".into_response();
    }

    // override blocks.dat 
    if kernel::block_override(block.clone()).await.unwrap() {
        // broadcast new block
        let _ = kernel::block_broadcast(block.clone());

        // clear transaction from transaction pool which is in block transactions
        let objs = kernel::processing_mutex_vector(block.clone()).await;
        conf::POOL.lock().unwrap().clear();
        for obj in objs {
            conf::POOL.lock().unwrap().push(obj);
        }
    } else {
        return "Block is already imported.".into_response();
    }    
    "Block update was successful.".into_response()
}


pub async fn handle_handshake(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(inv_message): extract::Json<InvMessage>) -> Response {
    // log request_ip
    info!("Handshake Request Received. SocketAddr:{}, imv_message.ip: {}", &addr.clone(), inv_message.clone().sender);

    // ip check
    if addr.clone().ip().to_string() != inv_message.clone().sender.to_string() {
        return (StatusCode::BAD_REQUEST, format!("Connection IP is invalid. ")).into_response();
    }

    let mut socket_url = format!("ws://{}:{}/ws", inv_message.clone().sender, conf::PORT);
    let mut protocol = "ipv4".to_string();
    if addr.clone().is_ipv6() {
        protocol = "ipv6".to_string();
        socket_url = format!("ws://[{}]:{}/ws", inv_message.clone().sender, conf::PORT);
    }

    let result = kernel::verify_node(socket_url, inv_message.clone(), protocol).await;
    match result {
        Ok(_) => {
            info!("Node verification process was successful.");
        }
        Err(error) => {
            info!("Node verification failed. {}", error);
            return (StatusCode::BAD_REQUEST, format!("Connection IP is invalid. ")).into_response();
        }
    }

    "The handshake was successful.".into_response()
}

pub async fn handle_ws(ConnectInfo(addr): ConnectInfo<SocketAddr>, ws: WebSocketUpgrade) -> Response {
    println!("web socket received: {}", addr);
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {

    let myaddress = address::get_address().unwrap();
    let mut bf = bloom::BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
    bf.set_v(myaddress.address.to_string());

    let mut bloom_str = String::new();
    for i in bf.filter {
        bloom_str = format!("{}{}", bloom_str, i);
    }
    println!("bloom str: {}", bloom_str);
    
    while let Some(msg) = socket.recv().await {
        let _msg = if let Ok(msg) = msg {
            msg
        } else {
            return;
        };
        if socket.send(bloom_str.clone().into()).await.is_err() {
            return;
        }
    }
}

pub async fn handle_fetch_peers(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(peers): extract::Json<Vec<kernel::Peer>>) -> Response {
    // log request_ip
    info!("Peers List Import Request: {}", &addr.clone());

    // check ip as SEED DNS
    if addr.clone().ip().to_string() != crypt::base64_decode(conf::SEED_DNS){
        info!("Requested ip is not SEED DNS.");
        return "Requested ip is not SEED DNS.".into_response();
    }

    let file_path = format!("{}", conf::PEERS_LIST);
    let mut file = File::create(file_path.clone()).unwrap();
    for peer in peers {
        let serialized: Vec<u8> = serde_json::to_vec(&peer).unwrap();
        file.write_all(&serialized).expect("write failed");
        file.write_all(b"\n").expect("write failed");
    }
    println!("done");

    return "Peers List Import was successful.".into_response();
}

pub async fn handle_fetch_blocks(ConnectInfo(addr): ConnectInfo<SocketAddr>, extract::Json(blocks): extract::Json<Vec<kernel::Block>>) -> Response {
    // log request_ip
    info!("Blocks List Import Request: {}", &addr.clone());

    // check ip as SEED DNS
    if addr.clone().ip().to_string() != crypt::base64_decode(conf::SEED_DNS){
        info!("Requested ip is not SEED DNS.");
        return "Requested ip is not SEED DNS.".into_response();
    }

    let file_path = format!("{}", conf::BLOCK_PATH);
    let mut file = File::create(file_path.clone()).unwrap();
    for block in blocks {
        let serialized: Vec<u8> = serde_json::to_vec(&block).unwrap();
        file.write_all(&serialized).expect("write failed");
        file.write_all(b"\n").expect("write failed");
    }
    println!("blocks fetch done");

    return "Blocks List Import was successful.".into_response();
}

pub async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, format!("I'm ACTIVE"))
}

async fn check_double_transfer(signed_transaction: kernel::SignedTransaction) -> bool {
    let public_key_decode = hex::decode(signed_transaction.clone().sender).unwrap();
    let mut binding = conf::POOL.lock().unwrap();
    let objs = binding.deref_mut();
    for obj in objs {
        if signed_transaction.signature == obj.signature {
            return false;
        } else if signed_transaction.sender == obj.sender && signed_transaction.receiver == obj.receiver && signed_transaction.amount == obj.amount && signed_transaction.nft_data == obj.nft_data && signed_transaction.nft_origin == obj.nft_origin {
            return false;
        } else if public_key_decode == conf::COINBASE_PUBKEY.to_owned().into_bytes() && obj.sender == signed_transaction.sender {
            return false;
        }
    }
    return true;
}

pub async fn check_double_transfer_in_blocks(signed_transaction: kernel::SignedTransaction) -> bool {

    let blocks: std::collections::VecDeque<kernel::Block> = utility::get_blocks().await.unwrap();
    for block in blocks {
        for transaction in block.transactions {
            if transaction == signed_transaction {
                return false;
            }
        }
    }
    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[tokio::test]
    async fn test_ipv4_or_ipv6() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192,168,33,10)), 3000);
        println!("{}", socket);
        assert_eq!(socket.port(), 3000);
        assert_eq!(socket.ip().to_string(), "192.168.33.10".to_string());
        assert_eq!(socket.is_ipv4(), true);

        let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        assert_eq!(socket.port(), 8080);
        assert_eq!(socket.ip().to_string(), "::1".to_string());
        assert_eq!(socket.is_ipv4(), false);
    }

    #[tokio::test]
    async fn test_check_double_transfer() {
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let utc_datetime_2: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:10:00+09:00").unwrap().into();
        let signed_transaction1 = kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: "029e1baf2992b44af147c306fb728f8b00e908aa7f09e25eaa0a2fed3f71ad4cf6".to_string(),
            receiver: "1E5b59jN4".to_string(),
            amount: 2000,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "eyJ0aW1lIjoiMjAyNS0w".to_string(),
        };

        let duplicated_transaction =  kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: "029e1baf2992b44af147c306fb728f8b00e908aa7f09e25eaa0a2fed3f71ad4cf6".to_string(),
            receiver: "1E5b59jN4".to_string(),
            amount: 2000,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "eyJ0aW1lIjoiMjAyNS0w".to_string(),
        };

        let same_receiver_same_amount_transaction =  kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime_2,
            sender: "029e1baf2992b44af147c306fb728f8b00e908aa7f09e25eaa0a2fed3f71ad4cf6".to_string(),
            receiver: "1E5b59jN4".to_string(),
            amount: 2000,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "xxxxxxxxxxxxxxxxxx".to_string(),
        };

        let new_transaction = kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: "029e1baf2992b44af147c306fb728f8b00e908aa7f09e25eaa0a2fed3f71ad4cf6".to_string(),
            receiver: "2222222222".to_string(),
            amount: 2000,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "33333333333".to_string(),
        };
        

        let length = conf::POOL.lock().unwrap().len();
        conf::POOL.lock().unwrap().push(signed_transaction1);

        assert_eq!(check_double_transfer(duplicated_transaction).await, false);
        assert_eq!(check_double_transfer(same_receiver_same_amount_transaction).await, false);
        assert_eq!(check_double_transfer(new_transaction).await, true);
        conf::POOL.lock().unwrap().pop();
        assert_eq!(conf::POOL.lock().unwrap().len(), length);

        let coinbase_transaction = kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: hex::encode(conf::COINBASE_PUBKEY).to_string(),
            receiver: "2222222222".to_string(),
            amount: conf::MINER_REWARD,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "33333333333".to_string(),
        };
        let disguise_transaction = kernel::SignedTransaction { 
            version: "1.0".to_string(),
            time: utc_datetime,
            sender: hex::encode(conf::COINBASE_PUBKEY).to_string(),
            receiver: "44444444444".to_string(),
            amount: conf::MINER_REWARD,
            nft_data: "".to_string(),
            nft_origin: "".to_string(),
            op_code: "".to_string(),
            signature: "55555555555".to_string(),
        };
        conf::POOL.lock().unwrap().push(coinbase_transaction);
        assert_eq!(check_double_transfer(disguise_transaction).await, false);
        conf::POOL.lock().unwrap().pop();
    }

    #[tokio::test]
    async fn test_handle_socket() {
        let address = "1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string();
        let mut bf = bloom::BloomFilter { filter: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]};
        bf.set_v(address);
    
        let mut bloom_str = String::new();
        for i in bf.filter {
            bloom_str = format!("{}{}", bloom_str, i);
        }
    
        let expected = "2122002222".to_string();
        assert_eq!(bloom_str, expected);
    }

}