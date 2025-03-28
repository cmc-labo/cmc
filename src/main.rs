use axum::middleware::{self};
use tower_http::services::{ServeDir, ServeFile};
use std::net::SocketAddr;
use axum_csrf::{CsrfConfig, CsrfLayer};
mod wallet; mod auth; mod crypt; mod address; mod conf; mod utility;
mod kernel; mod node; mod merkle; mod account; mod bloom; mod model;

#[tokio::main]
async fn main() {
    let serve_dir = ServeDir::new("static").not_found_service(ServeFile::new("static"));
    let config = CsrfConfig::default();
    let _ = utility::init_tracing();
    let app_state = model::connection_pool().await.unwrap();

    let public_router = axum::Router::new()
        .route("/login", axum::routing::get(wallet::handle_login))
        .route("/signup", axum::routing::get(wallet::handle_signup))
        .route("/error", axum::routing::get(wallet::handle_error))
        .route("/auth_login", axum::routing::post(auth::handle_auth_login))
        .route("/auth_signup", axum::routing::post(auth::handle_auth_signup))
        .route("/logout", axum::routing::get(auth::handle_logout));

    let private_router = axum::Router::new()
        .route("/home", axum::routing::get(wallet::handle_index))
        .route("/withdrawal", axum::routing::get(wallet::handle_withdrawal))
        .route("/withdrawal_complete", axum::routing::post(wallet::handle_withdrawal_complete))
        .route("/nft", axum::routing::get(wallet::handle_nft))
        .route("/nft_withdrawal", axum::routing::get(wallet::handle_nft_withdrawal))
        .route("/nft_withdrawal_complete", axum::routing::post(wallet::handle_nft_withdrawal_complete))
        .route("/nft_transfer/{param}", axum::routing::get(wallet::handle_nft_transfer))
        .route("/nft_transfer_complete", axum::routing::post(wallet::handle_nft_transfer_complete))
        .route("/address", axum::routing::get(wallet::handle_address))
        .route("/blocks", axum::routing::get(wallet::handle_blocks))
        .route("/history", axum::routing::get(wallet::handle_history))
        .route("/market", axum::routing::get(wallet::handle_market))
        .route("/swap", axum::routing::get(wallet::handle_swap))
        .route("/account", axum::routing::get(wallet::handle_account))
        .route("/account_username", axum::routing::get(wallet::handle_account_username))
        .route("/account_username_complete", axum::routing::post(wallet::handle_account_username_complete))
        .route("/account_password", axum::routing::get(wallet::handle_account_password))
        .route("/account_password_complete", axum::routing::post(wallet::handle_account_password_complete))
        .route("/account_nodetype", axum::routing::get(wallet::handle_account_nodetype))
        .route("/account_nodetype_complete", axum::routing::post(wallet::handle_account_nodetype_complete))
        .layer(middleware::from_fn_with_state(app_state.clone(), auth::auth_middleware));

    let node_router = axum::Router::new()
        .route("/transaction_pool", axum::routing::post(node::handle_transaction_pool))
        .route("/block_validate", axum::routing::post(node::handle_block_validate))
        .route("/block_update", axum::routing::post(node::handle_block_update))
        .route("/handshake", axum::routing::post(node::handle_handshake))
        .route("/ws", axum::routing::any(node::handle_ws))
        .route("/fetch_peers", axum::routing::post(node::handle_fetch_peers))
        .route("/fetch_blocks", axum::routing::post(node::handle_fetch_blocks))
        .route("/health", axum::routing::any(node::handle_health));
        
    let app = axum::Router::new()
        .merge(node_router)
        .merge(public_router)
        .merge(private_router)
        .nest_service("/static", serve_dir.clone())
        .fallback_service(serve_dir.clone())
        .layer(CsrfLayer::new(config))
        .with_state(app_state);
        
    let address = format!("0.0.0.0:{}",conf::PORT);    
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}