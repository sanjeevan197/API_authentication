use sqlx::MySqlPool;

pub async fn create_db_pool() -> MySqlPool {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    MySqlPool::connect(&db_url)
        .await
        .expect("Failed to connect to the database")
}
