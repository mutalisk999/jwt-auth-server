#[macro_use]
extern crate lazy_static;

use std::net::SocketAddr;
use flexi_logger::{detailed_format, Duplicate};
use log::info;
use tokio::signal;
use dotenv::dotenv;

use crate::router::register_router;
use crate::utils::g::{init_jwt_secret, init_mysql_rbatis_session};

mod router;
mod controller;
mod utils;
mod model;

fn init_log() {
    flexi_logger::Logger::with_str("debug")
        .log_to_file()
        .directory("log")
        .basename("jwt-auth-server.log")
        .duplicate_to_stdout(Duplicate::All)
        .format_for_files(detailed_format)
        .format_for_stdout(detailed_format)
        .start()
        .unwrap_or_else(|e| panic!("logger initialization failed, err: {}", e));
}

async fn shutdown_signal() {
    #[cfg(unix)]
        let ctrl_c = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install Ctrl+C handler")
            .recv()
            .await;
        info!("terminated by SIGINT");
    };

    #[cfg(not(unix))]
        let ctrl_c = async {
        signal::windows::ctrl_c().unwrap().recv()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("terminated by Ctrl+C");
    };

    #[cfg(unix)]
        let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
        info!("terminated by SIGTERM");
    };

    #[cfg(not(unix))]
        let terminate = async {
        signal::windows::ctrl_break().unwrap().recv()
            .await
            .expect("failed to install Ctrl+Break handler");
        info!("terminated by Ctrl+Break");
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() {
    // init log
    init_log();

    // init jwt secret and db session
    dotenv().ok();
    init_jwt_secret().await;
    init_mysql_rbatis_session().await;

    // run it
    let listen_addr_str = "0.0.0.0:4000";
    let listen_addr: SocketAddr = listen_addr_str.parse().unwrap();

    let router = register_router();

    info!("listening on {}", listen_addr);
    axum::Server::bind(&listen_addr)
        .serve(router.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}