use postgres::NoTls;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use jwtvault::prelude::*;

use jwtvault_examples::database::setup::connection;
use jwtvault_examples::database::users_setup::{signup_app_users, resolve_password_for_user};

struct PostgresDynamicVault {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    hasher: ArgonPasswordHasher,
}

impl Default for PostgresDynamicVault {
    fn default() -> Self {
        let pool = connection().ok().unwrap();
        let hasher = ArgonPasswordHasher::default();
        PostgresDynamicVault { pool, hasher }
    }
}

#[async_trait]
impl UserAuthentication for PostgresDynamicVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let password_from_disk = resolve_password_for_user(self.pool.clone(), user).await?;

        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let password_from_disk = password_from_disk.unwrap();
        let hash = password_from_disk.as_str();
        let result = self.hasher.verify_user_password(user, password, hash)?;
        if !result {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let session: Option<Session> = None;
        Ok(session)
    }
}

fn main() {
    dotenv::dotenv().ok();
    block_on(signup_app_users());

    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";


    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";

    let user_authentication = Box::new(PostgresDynamicVault::default());

    let mut vault = DynamicVault::default(user_authentication);

    let result = block_on(vault.login(
        user_john,
        password_for_john,
        None,
        None,
    ));

    assert!(result.is_ok());

    let result = block_on(vault.login(
        user_jane,
        password_for_jane,
        None,
        None,
    ));

    assert!(result.is_ok());
}