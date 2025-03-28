use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use anyhow::Result;
use dotenv::dotenv;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

pub async fn connection_pool()-> Result<AppState> {
    let _ = dotenv();
    let db_connection_str = format!("postgres://postgres:{}@localhost:5432", std::env::var("PSQL_PASSWORD").unwrap());
    let pool_result = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_connection_str)
        .await;

    let pool = match pool_result {
        Ok(pool) => pool,
        Err(err) => {
            eprint!("Error connecting to the database {}", err);
            return Err(err.into());
        }
    };
    let app_state = AppState { pool: pool };
    Ok(app_state)
}