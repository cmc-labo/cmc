use axum::extract::State;
use serde::{Serialize, Deserialize};
use sqlx::Row;
use anyhow::Result;
use crate::crypt;
use crate::model;

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub nodetype: String,
}

pub async fn get_user(State(state): State<model::AppState>) -> Result<User> {

    let row = sqlx::query("select * from users")
        .fetch_one(&state.pool)
        .await.unwrap();
    let id: i32 = row.try_get("id").unwrap();
    let name: String = row.try_get("username").unwrap();
    let password: String = row.try_get("password").unwrap();
    let nodetype: String = row.try_get("nodetype").unwrap();
    
    let user = User { id: id, username: name, password: password, nodetype: nodetype };
    Ok(user)
}

pub async fn username_update(State(state): State<model::AppState>, id: &i32, username: &String) -> Result<()> {

    let _ = sqlx::query("UPDATE users SET username = $1 WHERE id = $2")
        .bind(username)
        .bind(id)
        .execute(&state.pool)
        .await.unwrap();
    Ok(())
}

pub async fn password_update(State(state): State<model::AppState>, id: &i32, password: &String) -> Result<()> {  
    
    let hash_password = crypt::hash_password(&password);
    let _ = sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
        .bind(hash_password)
        .bind(id)
        .execute(&state.pool)
        .await.unwrap();
    Ok(())
}

pub async fn nodetype_update(State(state): State<model::AppState>, id: &i32, nodetype: &String) -> Result<()> {  

    let _ = sqlx::query("UPDATE users SET nodetype = $1 WHERE id = $2")
        .bind(nodetype)
        .bind(id)
        .execute(&state.pool)
        .await.unwrap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::{Client, NoTls};
    use dotenv::dotenv;
    use std::env;

    async fn psql_connect() -> Result<Client>  {
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
    async fn test_get_user() {
        let app_state = model::connection_pool().await.unwrap();
        let user: User = get_user(State(app_state)).await.unwrap();
        let client = psql_connect().await.unwrap();
        let mut expected_username: String = "".to_string();
        let mut expected_password: String = "".to_string();
        let mut expected_nodetype: String = "".to_string();
        for row in client.query("SELECT * From users WHERE id = $1", &[&user.id]).await.unwrap() {
            expected_username = row.get(1);
            expected_password = row.get(2);
            expected_nodetype = row.get(3);
        }
        assert_eq!(user.username, expected_username);
        assert_eq!(user.password, expected_password);
        assert_eq!(user.nodetype, expected_nodetype);
    }

    #[tokio::test]
    async fn test_username_update() {
        let app_state = model::connection_pool().await.unwrap();
        let current_user: User = get_user(State(app_state.clone())).await.unwrap();
        let _ = username_update(State(app_state.clone()), &current_user.id, &current_user.username).await.unwrap();
        let updated_user: User = get_user(State(app_state.clone())).await.unwrap();
        assert_eq!(current_user.username, updated_user.username);
    }

    #[tokio::test]
    async fn test_nodetype_update() {
        let app_state = model::connection_pool().await.unwrap();
        let current_user: User = get_user(State(app_state.clone())).await.unwrap();
        let _ = nodetype_update(State(app_state.clone()), &current_user.id, &current_user.nodetype).await.unwrap();
        let updated_user: User = get_user(State(app_state.clone())).await.unwrap();
        assert_eq!(current_user.nodetype, updated_user.nodetype);
    }

}