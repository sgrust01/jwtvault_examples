use jwtvault::prelude::*;
use postgres::NoTls;


use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use crate::database::setup::connection;


pub async fn signup_app_users() {
    let pool = connection().ok().unwrap();
    let loader = CertificateManger::default();
    let private_key = loader.password_hashing_secret();
    let secret_key = private_key.as_str();

    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";

    let hashed_password_for_john = hash_password_with_argon(
        password_for_john,
        secret_key,
    ).unwrap();
    let result = signup_user::<&str>(pool.clone(), &user_john, &hashed_password_for_john).await;
    if let Err(e) = result {
        let reason = e.to_string();
        eprintln!("Signup failed for user: {} Reason: {}", user_john, reason);
    };

    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";

    let hashed_password_for_jane = hash_password_with_argon(
        password_for_jane,
        loader.password_hashing_secret().as_str(),
    ).unwrap();
    let result = signup_user::<&str>(pool.clone(), &user_jane, &hashed_password_for_jane).await;
    if let Err(e) = result {
        let reason = e.to_string();
        eprintln!("Signup failed for user: {} Reason: {}", user_jane, reason);
    };
}

pub async fn resolve_password_for_user<T: AsRef<str>>(pool: Pool<PostgresConnectionManager<NoTls>>, user: T) -> Result<Option<String>, Error> {
    let mut conn = pool.get()?;
    let query = format!("SELECT user_password FROM tbl_users WHERE user_id = '{}' ", user.as_ref());
    let rs = conn.query(query.as_str(), &[])?;
    for row in rs {
        let rs: Option<String> = row.get(0);
        return Ok(rs);
    }
    return Ok(None);
}

pub async fn signup_user<T: AsRef<str>>(pool: Pool<PostgresConnectionManager<NoTls>>, user: T, password: T) -> Result<(), Error> {
    let mut conn = pool.get()?;
    let user = user.as_ref();
    let password = password.as_ref();
    // Watch out for SQL Injection
    let query = format!("INSERT INTO tbl_users VALUES ('{}', '{}')", user, password);
    let _ = conn.execute(query.as_str(), &[])?;
    Ok(())
}