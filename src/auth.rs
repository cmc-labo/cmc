use axum::{
    response::{IntoResponse,Redirect,AppendHeaders,Response},
    extract::{ConnectInfo,State},
    middleware::{Next},
    extract::Request
};
use axum_csrf::{CsrfToken};
use serde::{Serialize, Deserialize};
use sqlx::Row;
use anyhow::Result;
use tracing::info;
use std::net::SocketAddr;
use crate::crypt;
use crate::conf;
use crate::kernel;
use crate::address;
use crate::model;

#[derive(Serialize, Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    authenticity_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignupForm {
    username: String,
    password: String,
    node_type: String,
    authenticity_token: String,
}

pub async fn handle_auth_login(token: CsrfToken, State(state): State<model::AppState>, ConnectInfo(addr): ConnectInfo<SocketAddr>, axum::Form(loginform): axum::Form<LoginForm>)-> Response {

    // csrf token verify
    if token.verify(&loginform.authenticity_token).is_err() {
        info!("Invalid login attempt: {}", addr);
        return Redirect::to("/error").into_response();
    } else {
        println!("Login CSRF Token is valid: {}", addr);
    }

    // user register check
    if check_register_username(State(state.clone()), &loginform.username.clone()).await.unwrap() {
        println!("User is not registered: {}", addr);
        return Redirect::to("/error").into_response();
    }

    // password verify
    let password_hash = get_password_hash(State(state.clone()), &loginform.username).await.unwrap();
    if !crypt::password_verify(&loginform.password, &password_hash) {
        info!("Invalid password login: {}", addr);
        return Redirect::to("/error").into_response();
    } else {
        println!("Password is valid: {}", addr);
        info!("User login Success: {}, Username: {}", addr, &loginform.username);
    }

    // session_token set DB & Cookie(Max-Age is cooki valid seconds) 
    let session_token = crypt::create_session_token();
    let _ = session_token_db_save(State(state.clone()), &session_token.to_string()).await.unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("title", "Index page");

    let output = tera.render("index.html", &context);
    let cookie:String = format!("session_token={}; Max-Age={}", &session_token, conf::SESSION_TOKEN_MAX_AGE);
    let headers = AppendHeaders(vec![("Set-Cookie", cookie)]);
    (headers, axum::response::Html(output.unwrap())).into_response()
}

pub async fn handle_auth_signup(token: CsrfToken, State(state): State<model::AppState>, ConnectInfo(addr): ConnectInfo<SocketAddr>, axum::Form(signupform): axum::Form<SignupForm>)-> Response {

    // csrf token verify
    if token.verify(&signupform.authenticity_token).is_err() {
        info!("Invalid signup attempt: {}", addr);
        return Redirect::to("/error").into_response();
    } else {
        println!("Signup CSRF Token is valid: {}", addr);
    }

    // user register check
    if !check_register_user(State(state.clone())).await.unwrap() {
        println!("User is already registered: {}", addr);
        return Redirect::to("/login").into_response();
    }

    // node type check
    if signupform.node_type != "c".to_string() && signupform.node_type != "m".to_string() {
        info!("Node type format is wrong: {}", addr);
        return Redirect::to("/error").into_response();
    }

    // register user
    let hash_password = crypt::hash_password(&signupform.password);
    println!("{}", hash_password);
    let _ = user_db_register(State(state.clone()), &signupform.username, &hash_password, &signupform.node_type).await.unwrap();

    // log
    info!("Signup: {}, username: {}", addr, &signupform.username);

    // create address
    address::init_address();

    // handshake in a another thread
    let _ = tokio::spawn(async move {
        let _ = kernel::handshake(&signupform.node_type).await.unwrap();
    });

    // session_token set
    let session_token = crypt::create_session_token();
    let _ = session_token_db_save(State(state.clone()), &session_token.to_string()).await.unwrap();

    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("title", "Index page");

    let output = tera.render("index.html", &context);
    let cookie:String = format!("session_token={}; Max-Age={}", &session_token, conf::SESSION_TOKEN_MAX_AGE);
    let headers = AppendHeaders(vec![("Set-Cookie", cookie)]);
    (headers, axum::response::Html(output.unwrap())).into_response()
}

pub async fn handle_logout()-> impl IntoResponse{
    info!("Log out.");

    let tera = tera::Tera::new("templates/*").unwrap();

    let context = tera::Context::new();

    let output = tera.render("logout.html", &context);
    let cookie:String = format!("session_token=_");
    let headers = AppendHeaders(vec![("Set-Cookie", cookie)]);
    (headers, axum::response::Html(output.unwrap()))
}

async fn get_password_hash(State(state): State<model::AppState>, username: &String) -> Result<String> {
    let row = sqlx::query("select * from users where username= $1")
        .bind(username)
        .fetch_one(&state.pool)
        .await;
    match row {
        Ok(_) => {
        }
        Err(error) => {
            println!("{}", error);
            return Err(error.into());
        }
    }
    let password_hash: String = row.unwrap().try_get("password").unwrap();
    Ok(password_hash)
}

async fn session_token_db_save(State(state): State<model::AppState>, session_token: &String) -> Result<()> {
    // Only one session is stored in the session table at anytime.
    let _ = sqlx::query("TRUNCATE TABLE sessions;")
        .execute(&state.clone().pool)
        .await.unwrap();

    let _ = sqlx::query("INSERT INTO sessions (session_token) VALUES ($1)")
        .bind(session_token)
        .execute(&state.pool)
        .await.unwrap();
    Ok(())
}

async fn user_db_register(State(state): State<model::AppState>, username: &String, password: &String, nodetype: &String) -> Result<()> {
    println!("{} {} {}", username, password, nodetype);
    let _ = sqlx::query("INSERT INTO users (username, password, nodetype) VALUES ($1, $2, $3)")
        .bind(username)
        .bind(password)
        .bind(nodetype)
        .execute(&state.pool)
        .await.unwrap();
    Ok(())
}

pub async fn check_register_user(State(state): State<model::AppState>) -> Result<bool> {
    let row = sqlx::query("select * from users")
        .fetch_one(&state.pool)
        .await;
    match row {
        Ok(row) => {
            println!("{:?}", row);
            return Ok(false);
        }
        Err(error) => {
            println!("{}", error);
            return Ok(true);
        }
    }
}

pub async fn check_register_username(State(state): State<model::AppState>, username: &String) -> Result<bool> {
    let row = sqlx::query("select * from users where username= $1")
        .bind(username)
        .fetch_one(&state.pool)
        .await;
    match row {
        Ok(_) => {
            return Ok(false);
        }
        Err(error) => {
            println!("{}", error);
            return Ok(true);
        }
    }
}

pub async fn auth_middleware(State(state): State<model::AppState>, req: Request,
    next: Next,) -> impl IntoResponse {

    let session_token = req
        .headers()
        .get_all("Cookie")
        .into_iter()
        .flat_map(|cookie_header| cookie_header.to_str().ok())
        .map(|cookies_str| {
            cookie::Cookie::split_parse(cookies_str)
                .into_iter()
                .filter_map(|c| c.ok())
        })
        .flatten()
        .find(|cookie| cookie.name() == "session_token");
    
    if session_token == None {
        return Redirect::to("/login").into_response()
    } else if session_token.clone().unwrap().value() == "_" {
        return Redirect::to("/login").into_response()
    } else {
        let row = sqlx::query("SELECT id, session_token From sessions where session_token=$1")
            .bind(&session_token.clone().unwrap().value())
            .fetch_one(&state.pool)
            .await;
        match row {
            Ok(_row) => {
                // println!("{:?}", row);
            }
            Err(error) => {
                println!("{}", error);
                return Redirect::to("/login").into_response();
            }
        }
        let res = next.run(req).await;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::{Client, NoTls};
    use dotenv::dotenv;
    use std::env;

    async fn psql_connect() -> Result<Client, Box<dyn std::error::Error>>  {
        let _ = dotenv();
        let host = format!("host=localhost user=postgres password={}", env::var("PSQL_PASSWORD").unwrap());
        let (client, connection) = tokio_postgres::connect(&host, NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
        Ok(client)
    }

    #[tokio::test]
    async fn test_check_register_user() {
        let client = psql_connect().await.unwrap();
        let row = client.query("SELECT * FROM information_schema.tables WHERE table_name = 'users'", &[]).await.unwrap();
        assert_eq!(row.len(), 1);

        let mut expected = false;
        let rows = client.query("SELECT * FROM users", &[]).await.unwrap();
        if rows.len() == 0 { 
            expected = true;
        }
        let app_state = model::connection_pool().await.unwrap();
        let result = check_register_user(State(app_state.clone())).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_get_password_hash() {
        let client = psql_connect().await.unwrap();
        let rows = client.query("SELECT column_name FROM information_schema.columns where table_name = 'users'", &[]).await.unwrap();
        let colomn_name: String = rows[2].get(0);
        assert_eq!(colomn_name, "password".to_string());

        let name = "NOT_EXIT_USER".to_string();
        let app_state = model::connection_pool().await.unwrap();
        let result = get_password_hash(State(app_state.clone()),&name).await; 
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_token_db_save() {
        let app_state = model::connection_pool().await.unwrap();
        let session_token = "123456789".to_string();
        let _ = session_token_db_save(State(app_state.clone()), &session_token).await.unwrap();
        let client = psql_connect().await.unwrap();
        let mut result: String = "".to_string();
        for row in client.query("SELECT id, session_token From sessions", &[]).await.unwrap() {
            result = row.get(1);
        }
        assert_eq!(session_token, result);
    }

    #[tokio::test]
    async fn test_user_db_register() {
        let app_state = model::connection_pool().await.unwrap();
        let username = "test_alice".to_string();
        let password = "$2y$10$RGCABC0pdO3N/SQtrfmD1exvKUnZl7Px8TzH9AN0viskofay9eU0a".to_string();
        let node_type = "c".to_string();
        let _ = user_db_register(State(app_state.clone()), &username, &password, &node_type).await.unwrap();

        let client = psql_connect().await.unwrap();
        let mut result: String = "".to_string();
        for row in client.query("SELECT password From users WHERE username = $1", &[&username]).await.unwrap() {
            result = row.get(0);
        }
        assert_eq!(result, password);

        client.execute(
            "DELETE FROM users WHERE username = $1",
            &[&username],
        ).await.unwrap();        
    }
}