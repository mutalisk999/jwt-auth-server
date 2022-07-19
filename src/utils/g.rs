use std::env;
use std::sync::Arc;

use rbatis::core::db::{DBConnectOption, DBPoolOptions};
use rbatis::core::Error;
use rbatis::crud::CRUD;
use rbatis::crud_table;
use rbatis::rbatis::Rbatis;
use sqlx_core::mysql::MySqlConnectOptions;
use tokio::sync::RwLock;

lazy_static! {
    pub static ref RB_SESSION: Arc::<RwLock<Option<Rbatis>>> = Arc::new(RwLock::new(None));
    pub static ref JWT_SECRET: Arc::<RwLock<Vec<u8>>> = Arc::new(RwLock::new(Vec::new()));
}


pub async fn init_mysql_rbatis_session() {
    let mysql_host = env::var("MYSQL_HOST")
        .unwrap_or_else(|e| panic!("no MYSQL_HOST in .env: {}", e.to_string()));
    let mysql_port = env::var("MYSQL_PORT")
        .unwrap_or_else(|e| panic!("no MYSQL_PORT in .env: {}", e.to_string()))
        .parse::<u16>()
        .unwrap();
    let mysql_db = env::var("MYSQL_DB")
        .unwrap_or_else(|e| panic!("no MYSQL_DB in .env: {}", e.to_string()));
    let mysql_user = env::var("MYSQL_USER")
        .unwrap_or_else(|e| panic!("no MYSQL_USER in .env: {}", e.to_string()));
    let mysql_pass = env::var("MYSQL_PASS")
        .unwrap_or_else(|e| panic!("no MYSQL_PASS in .env: {}", e.to_string()));

    let rb = Rbatis::new();
    let db_cfg = MySqlConnectOptions::new();
    let db_cfg = db_cfg
        .host(&mysql_host)
        .port(mysql_port)
        .database(&mysql_db)
        .username(&mysql_user)
        .password(&mysql_pass);

    let db_cfg = DBConnectOption::from_mysql(&db_cfg)
        .unwrap_or_else(|e| panic!("from_mysql: {:?}", e));
    rb.link_cfg(&db_cfg, DBPoolOptions::new())
        .await
        .unwrap_or_else(|e| panic!("link_cfg: {:?}", e));

    let mut rb_session = RB_SESSION
        .as_ref()
        .write()
        .await;
    *rb_session = Some(rb);
}

pub async fn init_jwt_secret() {
    let jwt_secret = env::var("JWT_SECRET")
        .unwrap_or_else(|e| panic!("no JWT_SECRET in .env: {}", e.to_string()));

    JWT_SECRET
        .as_ref()
        .write()
        .await
        .append(&mut jwt_secret.as_bytes().to_vec());
}