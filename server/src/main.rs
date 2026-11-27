#[tokio::main]
async fn main() {
    let addr = std::env::var("PLAINTEXT_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let db_path = std::env::var("PLAINTEXT_DB").unwrap_or_else(|_| "plaintext.db".into());
    let db = plaintext_server::open_db(&db_path).expect("open database");
    let backup_db = db_path.clone();
    std::thread::spawn(move || {
        loop {
            if let Err(e) = plaintext_server::backup_copy(&backup_db) {
                eprintln!("backup copy of {backup_db} failed: {e}");
            }
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let cfg = plaintext_server::Config {
        setup_code: env("PLAINTEXT_SETUP_CODE"),
        open_signup: env("PLAINTEXT_SIGNUP").is_some_and(|v| v == "open"),
        hosts: env("PLAINTEXT_URL").map(|v| v.split(',').map(plaintext_core::crypto::server_host).collect()).unwrap_or_default(),
    };
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("plaintext listening on {addr}, database {db_path}");
    axum::serve(listener, plaintext_server::app(db, cfg)).await.expect("serve");
}
