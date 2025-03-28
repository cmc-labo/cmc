use axum::{
    response::{IntoResponse,Redirect,Response},
    extract::{ConnectInfo,Multipart,State}
};
use axum_csrf::{CsrfToken};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use tracing::info;
use std::collections::{HashMap,VecDeque};
use std::net::SocketAddr;
use std::fs::File;
use std::path::PathBuf;
use std::io::{Write, BufReader, BufRead};
use std::{fs};
use crate::auth;
use crate::crypt;
use crate::address;
use crate::account;
use crate::utility;
use crate::kernel;
use crate::conf;
use crate::model;

#[derive(Serialize, Deserialize)]
pub struct WithdrawalForm {
    receiver: String,
    amount: i32,
    authenticity_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct UsernameForm {
    username: String,
    authenticity_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordForm {
    password: String,
    authenticity_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct NodetypeForm {
    nodetype: String,
    authenticity_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferForm {
    receiver: String,
    nft_origin: String,
    authenticity_token: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
struct NftData {
    time: DateTime<Utc>,
    sender: String,
    signature: String,
    nft_data: String,
    transaction_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TransactionHistory {
    transceiver: String,
    time: DateTime<Utc>,
    sender: String,
    receiver: String,
    amount: i32,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[allow(non_snake_case)]
pub struct Rate {
    pub id: String,
    pub symbol: String,
    // currencySymbol: String,
    pub r#type: String,
    pub rateUsd: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[allow(non_snake_case)]
struct RateSwap {
    id: String,
    symbol: String,
    rateUsd: f32,
    rateBtc: f32,
}

pub async fn handle_login(token: CsrfToken)-> impl IntoResponse {

    let authenticity_token = token.authenticity_token().unwrap();
    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("authenticity_token", &authenticity_token);

    let output = tera.render("login.html", &context);
    (token, axum::response::Html(output.unwrap()))
}

pub async fn handle_signup(token: CsrfToken, State(state): State<model::AppState>)-> impl IntoResponse {
    let mut register = false;
    if !auth::check_register_user(State(state)).await.unwrap() {
        register = true;
    }
    let authenticity_token = token.authenticity_token().unwrap();
    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("authenticity_token", &authenticity_token);
    context.insert("register", &register);

    let output = tera.render("signup.html", &context);
    (token, axum::response::Html(output.unwrap()))
}

pub async fn handle_index()-> axum::response::Html<String>{

    let mut blocks: VecDeque<kernel::Block> = utility::get_blocks().await.unwrap();
    if blocks.len() > 5 {
        blocks.drain(5..);
    }
    let mut balance: i32 = utility::balance().unwrap();
    if balance < 0 {
        balance = 0;
    }
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("balance", &balance);
    context.insert("data", &blocks);
    let output = tera.render("home.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_blocks()-> axum::response::Html<String>{

    let mut blocks: VecDeque<kernel::Block> = utility::get_blocks().await.unwrap();
    if blocks.len() > 20 {
        blocks.drain(20..);
    };
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("data", &blocks);
    let output = tera.render("blocks.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_history()-> axum::response::Html<String>{

    let blocks = utility::get_blocks().await.unwrap();
    let my_address: address::MyAddress = address::get_address().unwrap();

    let data = transaction_history(blocks, my_address).await;

    let balance = utility::balance().unwrap();
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("balance", &balance);
    context.insert("data", &data);
    let output = tera.render("history.html", &context);
    axum::response::Html(output.unwrap())
}

async fn transaction_history(blocks: VecDeque<kernel::Block>, my_address: address::MyAddress) -> Vec<TransactionHistory> {
    let mut data: Vec<TransactionHistory> = Vec::new();
    for block in blocks {
        for transaction in block.transactions {
            if transaction.amount != 0 {
                if transaction.sender == my_address.public_key {
                    let t = TransactionHistory { transceiver:"sender".to_string(), time: transaction.time, sender:"-".to_string(), receiver:transaction.receiver, amount:transaction.amount};
                    data.push(t);
                } else if transaction.receiver == my_address.address {
                    let t = TransactionHistory { transceiver:"receiver".to_string(), time: transaction.time, sender:transaction.sender, receiver:"-".to_string(), amount:transaction.amount};
                    data.push(t);
                }
            }
        }
    }
    return data;
}

pub async fn handle_withdrawal(token: CsrfToken)-> axum::response::Html<String>{

    let authenticity_token = token.authenticity_token().unwrap();

    let mut balance: i32 = utility::balance().unwrap();
    if balance < 0 {
        balance = 0;
    }

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();

    context.insert("authenticity_token", &authenticity_token);
    context.insert("balance", &balance);
    let output = tera.render("withdrawal.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_nft_withdrawal(token: CsrfToken)-> axum::response::Html<String>{

    let authenticity_token = token.authenticity_token().unwrap();
    let aws_credential = kernel::check_aws_credential().await;

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();

    context.insert("authenticity_token", &authenticity_token);
    context.insert("aws_credential", &aws_credential);
    let output = tera.render("nft_withdrawal.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_withdrawal_complete(token: CsrfToken, ConnectInfo(addr): ConnectInfo<SocketAddr>, axum::Form(withdrawalform): axum::Form<WithdrawalForm>)-> Response{

    // csrf token verify
    if token.verify(&withdrawalform.authenticity_token).is_err() {
        println!("Crypt Withdrawal CSRF Token is invalid");
        return Redirect::to("/error").into_response();
    } else {
        println!("Crypt Withdrawal CSRF Token is Valid.");
    }

    // log
    info!("CryptWidrawal: {}, Receiver: {}, Amount: {}", addr, &withdrawalform.receiver, &withdrawalform.amount);

    // transaction broadcast with another thread
    let nft_data = "".to_string();
    let nft_origin = "".to_string();
    let _ = tokio::spawn(async move {
        let _ = kernel::transaction(&withdrawalform.receiver, &withdrawalform.amount, &nft_data, &nft_origin).await;
    });
    
    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_nft_withdrawal_complete(token: CsrfToken, mut multipart: Multipart)-> Response{

    let mut receiver = "".to_string(); 
    let mut nft_tmp_path = "".to_string();

    while let Some(field) = multipart.next_field().await.unwrap(){
        let param_name = field.name().unwrap().to_string();
        match param_name.as_str() {
            "authenticity_token" => {
                let authenticity_token = field.text().await.unwrap();
                if token.verify(&authenticity_token).is_err() {
                    println!("NFT Withdrawal CSRF Token is invalid");
                    return Redirect::to("/error").into_response();
                } else {
                    println!("NFT Withdrawal CSRF Token is Valid lets do stuff!");
                }
            }
            "receiver" => {
                receiver = field.text().await.unwrap();
            }
            "nftFile" => {
                let file_name = match field.file_name() {
                    Some(name) => name.to_owned(),
                    None => panic!("file_name is None"),
                };
                match field.bytes().await {
                    Ok(data) => {
                        let tmp_path = format!("{}{}", conf::NFT_TMP_PATH, file_name);
                        let mut file = File::create(tmp_path.clone()).unwrap();
                        file.write_all(&data).unwrap();

                        info!("NFT Withdrawal request, length of `{}` is {} bytes", file_name, data.len());
                    }
                    Err(e) => {
                        eprintln!("Error reading `{}`: {}", param_name, e);
                        // return;
                    }
                }
                let pathbuf = PathBuf::from(format!("{}{}", conf::NFT_TMP_PATH, file_name));
                let ext_string = pathbuf
                    .extension()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let ex_filename = format!("{}{}", conf::NFT_TMP_PATH, file_name);
                nft_tmp_path = format!("{}nft.{}", conf::NFT_TMP_PATH, ext_string);
                fs::rename(ex_filename, nft_tmp_path.clone()).unwrap();
            }
            _ => {
                println!("unknown param_name: {}", param_name);
            }
        }
    }    

    let nft_data: String = kernel::upload_nft_to_ipfs(nft_tmp_path).await.unwrap();
    let amount = 0;
    let nft_origin = "".to_string();
    let _ = tokio::spawn(async move {
        let _ = kernel::transaction(&receiver, &amount, &nft_data, &nft_origin).await;
    });

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_nft()-> axum::response::Html<String>{

    let my_address: address::MyAddress = address::get_address().unwrap();
    let mut nft_objs: Vec<NftData> = Vec::new();

    let mut blocks: Vec<kernel::Block> = Vec::new();
    for result in BufReader::new(File::open(conf::BLOCK_PATH).unwrap()).lines() {
        let l = result;
        let param:kernel::Block = serde_json::from_str(&l.unwrap()).unwrap();
        blocks.push(param);
    }

    let mut transaction_pool: Vec<kernel::SignedTransaction> = Vec::new();
    for block in blocks {
        for transaction in block.transactions {
            transaction_pool.push(transaction);
        }
    } 

    let nft_holder:HashMap<String, String> = utility::nft_calc(transaction_pool);
    for (k, v) in nft_holder {
        if v == my_address.address { 
            let transaction_str = crypt::base64_decode(&k);
            let transaction:kernel::SignedTransaction = serde_json::from_str(&transaction_str).unwrap();
            let nft_obj = NftData { time: transaction.time, sender: transaction.sender, signature: transaction.signature, nft_data: crypt::base64_decode(&transaction.nft_data), transaction_hash: k};
            nft_objs.push(nft_obj);
        }
    }
    println!("{:?}", nft_objs);

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("nft_objs", &nft_objs);
    let output = tera.render("nft.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_nft_transfer(token: CsrfToken, axum::extract::Path(param): axum::extract::Path<String>)-> axum::response::Html<String>{

    let transaction_str = crypt::base64_decode(&param);
    let transaction:kernel::SignedTransaction = serde_json::from_str(&transaction_str).unwrap();
    let nft_obj = NftData { time: transaction.time, sender: transaction.sender, signature: transaction.signature, nft_data: crypt::base64_decode(&transaction.nft_data), transaction_hash: param};
    let authenticity_token = token.authenticity_token().unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();

    context.insert("authenticity_token", &authenticity_token);
    context.insert("nft_obj", &nft_obj);
    let output = tera.render("nft_transfer.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_nft_transfer_complete(token: CsrfToken, axum::Form(transferform): axum::Form<TransferForm>)-> Response{

    // csrf token verify
    if token.verify(&transferform.authenticity_token).is_err() {
        println!("NFT Transfer CSRF Token is invalid");
        return Redirect::to("/error").into_response();
    } else {
        println!("NFT Transfer CSRF Token is Valid lets do stuff!");
    }

    let amount: i32 = 0;
    let nft_data = "".to_string();
    let _ = tokio::spawn(async move {
        let _ = kernel::transaction(&transferform.receiver, &amount, &nft_data, &transferform.nft_origin).await;
    });

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_address()-> axum::response::Html<String>{

    let my_address: address::MyAddress = address::get_address().unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("private_key", &my_address.private_key);
    context.insert("public_key", &my_address.public_key);
    context.insert("address", &my_address.address);
    let output = tera.render("address.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_market()-> axum::response::Html<String>{

    let mut btc_price = "".to_string();
    let mut eth_price = "".to_string();
    let mut sol_price = "".to_string();
    let mut ada_price = "".to_string();
    let mut avax_price = "".to_string();
    let mut xrp_price = "".to_string();

    let coins = utility::get_price().await.unwrap();
    let objs: Vec<Rate> = serde_json::from_value(coins).unwrap();
    for obj in objs {
        match obj.symbol {
            val if val == "BTC".to_string() => btc_price = obj.rateUsd,
            val if val == "ETH".to_string() => eth_price = obj.rateUsd,
            val if val == "SOL".to_string() => sol_price = obj.rateUsd,
            val if val == "ADA".to_string() => ada_price = obj.rateUsd,
            val if val == "AVAX".to_string() => avax_price = obj.rateUsd,
            val if val == "XRP".to_string() => xrp_price = obj.rateUsd,
            _ => (),
        }
    }

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("btc_price", &btc_price.parse::<f32>().unwrap());
    context.insert("eth_price", &eth_price.parse::<f32>().unwrap());
    context.insert("sol_price", &sol_price.parse::<f32>().unwrap());
    context.insert("ada_price", &ada_price.parse::<f32>().unwrap());
    context.insert("avax_price", &avax_price.parse::<f32>().unwrap());
    context.insert("xrp_price", &xrp_price.parse::<f32>().unwrap());
    let output = tera.render("market.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_swap()-> axum::response::Html<String>{

    let coins = utility::get_price().await.unwrap();

    let objs: Vec<Rate> = serde_json::from_value(coins).unwrap();
    let data = calc_swap_rate(objs).await;

    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("data", &data);
    let output = tera.render("swap.html", &context);
    axum::response::Html(output.unwrap())
}

async fn calc_swap_rate(objs: Vec<Rate>) -> Vec<RateSwap> {
    let mut btc_rate: f32 = 0.0;

    let mut crypt_objs: Vec<Rate> = Vec::new();
    for obj in objs {
        if obj.r#type == "crypto" {
            if obj.symbol == "BTC" {
                crypt_objs.insert(0, obj.clone());
                btc_rate = obj.rateUsd.parse::<f32>().unwrap();
            } else {
                crypt_objs.push(obj);
            }   
        }
    }

    let mut data: Vec<RateSwap> = vec![];
    for crypt_obj in crypt_objs {
        let obj = RateSwap { id: crypt_obj.id, symbol: crypt_obj.symbol, rateUsd: crypt_obj.rateUsd.clone().parse::<f32>().unwrap(), rateBtc: crypt_obj.rateUsd.parse::<f32>().unwrap() / &btc_rate };
        data.push(obj);
    }
    data.sort_by(|a, b| a.rateBtc.partial_cmp(&b.rateBtc).unwrap().reverse());
    return data;
}

pub async fn handle_account(State(state): State<model::AppState>)-> axum::response::Html<String>{

    let user: account::User = account::get_user(State(state)).await.unwrap();
    
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("username", &user.username);
    context.insert("nodetype", &user.nodetype);
    let output = tera.render("account.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_account_username(token: CsrfToken, State(state): State<model::AppState>)-> axum::response::Html<String>{

    let authenticity_token = token.authenticity_token().unwrap();
    let user: account::User = account::get_user(State(state)).await.unwrap();
    
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("authenticity_token", &authenticity_token);
    context.insert("username", &user.username);
    context.insert("nodetype", &user.nodetype);
    let output = tera.render("account_username.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_account_username_complete(token: CsrfToken, State(state): State<model::AppState>, axum::Form(usernameform): axum::Form<UsernameForm>)-> Response{

    // csrf token verify
    if token.verify(&usernameform.authenticity_token).is_err() {
        println!("Username Update CSRF Token is invalid");
        return Redirect::to("/error").into_response();
    } else {
        println!("Username Update CSRF Token is valid");
    }

    let user: account::User = account::get_user(State(state.clone())).await.unwrap();
    let _ = account::username_update(State(state.clone()), &user.id, &usernameform.username).await.unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_account_password(token: CsrfToken, State(state): State<model::AppState>)-> axum::response::Html<String>{

    let authenticity_token = token.authenticity_token().unwrap();
    let user: account::User = account::get_user(State(state)).await.unwrap();
    
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("authenticity_token", &authenticity_token);
    context.insert("username", &user.username);
    context.insert("nodetype", &user.nodetype);
    let output = tera.render("account_password.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_account_password_complete(token: CsrfToken, State(state): State<model::AppState>, axum::Form(passwordform): axum::Form<PasswordForm>)-> Response{

    // csrf token verify
    if token.verify(&passwordform.authenticity_token).is_err() {
        println!("Password Update CSRF Token is invalid");
        return Redirect::to("/error").into_response();
    } else {
        println!("Password Update CSRF Token is valid");
    }

    let user: account::User = account::get_user(State(state.clone())).await.unwrap();
    let _ = account::password_update(State(state.clone()), &user.id, &passwordform.password).await.unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_account_nodetype(token: CsrfToken, State(state): State<model::AppState>)-> axum::response::Html<String>{

    let authenticity_token = token.authenticity_token().unwrap();
    let user: account::User = account::get_user(State(state)).await.unwrap();
    
    let tera = tera::Tera::new("templates/*").unwrap();
    let mut context = tera::Context::new();
    context.insert("authenticity_token", &authenticity_token);
    context.insert("username", &user.username);
    context.insert("nodetype", &user.nodetype);
    let output = tera.render("account_nodetype.html", &context);
    axum::response::Html(output.unwrap())
}

pub async fn handle_account_nodetype_complete(token: CsrfToken, State(state): State<model::AppState>, axum::Form(nodetypeform): axum::Form<NodetypeForm>)-> Response{

    // csrf token verify
    if token.verify(&nodetypeform.authenticity_token).is_err() {
        println!("NodeType Update CSRF Token is invalid");
        return Redirect::to("/error").into_response();
    } else {
        println!("NodeType Update CSRF Token is valid");
    }

    let user: account::User = account::get_user(State(state.clone())).await.unwrap();
    let _ = account::nodetype_update(State(state.clone()), &user.id, &nodetypeform.nodetype).await.unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("complete.html", &context);
    axum::response::Html(output.unwrap()).into_response()
}

pub async fn handle_error()-> axum::response::Html<String>{

    let tera = tera::Tera::new("templates/*").unwrap();
    let context = tera::Context::new();
    let output = tera.render("error.html", &context);
    axum::response::Html(output.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use std::path::Path;

    #[tokio::test]
    async fn test_market_price() {

        // test data
        let objs: Vec<Rate> = vec![Rate { id: "bitcoin".to_string(), symbol: "BTC".to_string(), r#type: "crypto".to_string(), rateUsd: "92512.3238923002545161".to_string() }, Rate { id: "ethereum".to_string(), symbol: "ETH".to_string(), r#type: "crypto".to_string(), rateUsd: "2356.1020773758144847".to_string() }];

        let mut btc_price = "".to_string();
        let mut eth_price = "".to_string();
        for obj in objs {
            match obj.symbol {
                val if val == "BTC".to_string() => btc_price = obj.rateUsd,
                val if val == "ETH".to_string() => eth_price = obj.rateUsd,
                _ => (),
            }
        }
        assert_eq!(btc_price, "92512.3238923002545161".to_string());
        assert_eq!(eth_price, "2356.1020773758144847".to_string());
    }

    #[tokio::test]
    async fn test_calc_swap_rate() {
        // test data
        let btc_rate = "9000.00".to_string();
        let eth_rate = "2300.00".to_string();
        let sol_rate = "160.00".to_string();
        let objs: Vec<Rate> = vec![Rate { id: "bitcoin".to_string(), symbol: "BTC".to_string(), r#type: "crypto".to_string(), rateUsd: btc_rate }, Rate { id: "ethereum".to_string(), symbol: "ETH".to_string(), r#type: "crypto".to_string(), rateUsd: eth_rate }, Rate { id: "solana".to_string(), symbol: "SOL".to_string(), r#type: "crypto".to_string(), rateUsd: sol_rate}];

        let data = calc_swap_rate(objs).await;

        let expected: f32 = 2300.00 / 9000.00;
        assert_eq!(data[0].symbol, "BTC".to_string());
        assert_eq!(data[1].symbol, "ETH".to_string());
        assert_eq!(data[1].rateBtc, expected);
    }

    #[tokio::test]
    async fn test_transaction_history() {
        // test data
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let my_address = address::MyAddress {private_key: "".to_string(), public_key: "alice".to_string(), address: "ca55d5746f0e1b".to_string()};
        let signed_transaction1 = kernel::SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "alice".to_string(), receiver:"C229797C82F9D5".to_string(), amount: 10, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(),op_code:"".to_string()};
        let signed_transaction2 = kernel::SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "bob".to_string(), receiver:"ca55d5746f0e1b".to_string(), amount: 5, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(),op_code:"".to_string()};
        let signed_transaction3 = kernel::SignedTransaction {version:"".to_string(), time: utc_datetime, sender: "carol".to_string(), receiver:"2CEDE67EB49A01DC".to_string(), amount: 15, nft_data: "".to_string(), nft_origin: "".to_string(), signature: "".to_string(),op_code:"".to_string()};
        let mut transactions: Vec<kernel::SignedTransaction>  = Vec::new();
        transactions.push(signed_transaction1);
        transactions.push(signed_transaction2);
        transactions.push(signed_transaction3);
        let block1 = kernel::Block {version:"".to_string(), time: utc_datetime, transactions: transactions, hash: "".to_string(), nonce: "".to_string(), merkle: "".to_string(), miner:"".to_string(), validator: "".to_string(), op: "".to_string()};
        let mut blocks: VecDeque<kernel::Block> = VecDeque::new();
        blocks.push_back(block1);

        let data = transaction_history(blocks, my_address).await;
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].amount, 10);
        assert_eq!(data[1].sender, "bob".to_string());
    }

    #[tokio::test]
    async fn test_nft_calc() {
        // test data
        let utc_datetime: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-01-01T19:00:00+09:00").unwrap().into();
        let mut transaction_pool: Vec<kernel::SignedTransaction> = Vec::new();
        let transaction1 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string(), amount: 0, nft_data:"TkZUIERhdGEx".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let transaction_hash: String = BASE64_STANDARD.encode(serde_json::to_vec(&crypt::sign_transaction(&transaction1).unwrap()).unwrap());
        let transaction2 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"bob".to_string(), receiver:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), amount: 0, nft_data:"".to_string(),nft_origin:transaction_hash.to_string(),op_code:"".to_string()};
        let transaction3 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string(), amount: 0, nft_data:"TkZUIERhdGEy".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};
        let transaction4 = kernel::UnsignedTransaction {version:"1.0".to_string(), time:utc_datetime, sender:"alice".to_string(), receiver:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), amount: 1000, nft_data:"".to_string(),nft_origin:"".to_string(),op_code:"".to_string()};

        transaction_pool.push(crypt::sign_transaction(&transaction1).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction2).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction3).unwrap());
        transaction_pool.push(crypt::sign_transaction(&transaction4).unwrap());

        // calc my nft
        let address = "1E5b59jN4nyM9kpzqdXfW7MkLJ2CApAVjT".to_string();
        let mut nft_objs: Vec<NftData> = Vec::new();
        let nft_holder:HashMap<String, String> = utility::nft_calc(transaction_pool);
        for (k, v) in nft_holder {
            if v == address { 
                let transaction_str = crypt::base64_decode(&k);
                let transaction:kernel::SignedTransaction = serde_json::from_str(&transaction_str).unwrap();
                let nft_obj = NftData { time: transaction.time, sender: transaction.sender, signature: transaction.signature, nft_data: crypt::base64_decode(&transaction.nft_data), transaction_hash: k};
                nft_objs.push(nft_obj);
            }
        }
        assert_eq!(nft_objs.len(), 2);
    }

    #[tokio::test]
    async fn test_nft_withdrawal_complete_file_rename() {
        let file_name = "foo.txt";
        let file_path = format!("{}{}", conf::NFT_TMP_PATH, file_name);
        let mut file = File::create(file_path.clone()).unwrap();
        file.write_all(b"Hello, world!").unwrap();

        let pathbuf = PathBuf::from(file_path.clone());
        let ext_string = pathbuf
            .extension()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        println!("{}", ext_string);
        assert_eq!(ext_string, "txt".to_string());

        let new_file = format!("{}nft.{}",conf::NFT_TMP_PATH, ext_string);
        fs::rename(file_path, new_file.clone()).unwrap();
        
        assert_eq!(Path::new(&new_file).exists(), true);
        fs::remove_file(new_file).unwrap();
    }
}