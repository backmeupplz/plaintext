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
        quota: env("PLAINTEXT_QUOTA_MB").map(|v| v.parse::<u64>().ok().and_then(|mb| mb.checked_mul(1 << 20)).expect("PLAINTEXT_QUOTA_MB is a whole number of megabytes")),
        trust_proxy: env("PLAINTEXT_TRUST_PROXY").is_some_and(|v| v == "1"),
        hsts: env("PLAINTEXT_URL").is_some_and(|v| plaintext_server::https_url(&v)),
        pull_page: None,
        stage_slack: None,
    };
    let empty = db.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0)).expect("read database") == 0;
    if cfg.open_signup && cfg.setup_code.is_none() && empty {
        eprintln!("PLAINTEXT_SIGNUP=open needs PLAINTEXT_SETUP_CODE too while the server has no accounts, or whoever signs up first becomes the admin");
        std::process::exit(1);
    }
    if cfg.hosts.is_empty() {
        eprintln!("warning: PLAINTEXT_URL is not set, so only this machine (localhost) can sign in; set it to the address clients use");
    }
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("plaintext listening on {addr}, database {db_path}");
    plaintext_server::serve(listener, db, cfg).await.expect("serve");
}
