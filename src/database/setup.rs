use failure::Error;
use crate::database::db_common::{pg_pool_config_from_env, pg_connection_config_from_env, PoolConfig, ConnectionConfig};
use crate::database::r2d2_pool::create_r2d2_pool;
use crate::database::errors::DatabaseErrors::ConnectionFailed;


pub fn signup_user<T: AsRef<str>>(user: T, password: T) -> Result<(), Error> {
    let pool_config: Result<PoolConfig, Error> = pg_pool_config_from_env().map_err(|e| {
        ConnectionFailed("Bad PoolConfig".to_string(), e).into()
    });
    let pool_config = pool_config?;
    let conn_config:Result<ConnectionConfig, Error> = pg_connection_config_from_env().map_err(|e| {
        ConnectionFailed("Bad Connection Config".to_string(), e).into()
    });
    let conn_config = conn_config?;
    let pool = create_r2d2_pool(conn_config, pool_config)?;
    let mut conn = pool.get()?;
    let user = user.as_ref();
    let password = password.as_ref();
    // Watch out for SQL Injection
    let query = format!("INSERT INTO tbl_users VALUES ('{}', '{}')", user, password);
    let _ = conn.execute(query.as_str(), &[])?;
    Ok(())
}