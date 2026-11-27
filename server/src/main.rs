#[tokio::main]
async fn main() {
    let addr = std::env::var("PLAINTEXT_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let db_path = std::env::var("PLAINTEXT_DB").unwrap_or_else(|_| "plaintext.db".into());
    let invite = std::env::var("PLAINTEXT_INVITE").ok().filter(|s| !s.is_empty());
    let db = plaintext_server::open_db(&db_path).expect("open database");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("plaintext listening on {addr}, database {db_path}");
    axum::serve(listener, plaintext_server::app(db, invite)).await.expect("serve");
}
