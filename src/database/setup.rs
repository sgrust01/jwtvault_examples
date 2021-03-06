use failure::Error;
use crate::database::db_common::{pg_pool_config_from_env, pg_connection_config_from_env, PoolConfig, ConnectionConfig};
use crate::database::r2d2_pool::create_r2d2_pool;
use crate::database::errors::DatabaseErrors::ConnectionFailed;

use postgres::NoTls;


use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;


pub fn connection() -> Result<Pool<PostgresConnectionManager<NoTls>>, Error>{
    let pool_config: Result<PoolConfig, Error> = pg_pool_config_from_env().map_err(|e| {
        ConnectionFailed("Bad PoolConfig".to_string(), e).into()
    });
    let pool_config = pool_config?;
    let conn_config:Result<ConnectionConfig, Error> = pg_connection_config_from_env().map_err(|e| {
        ConnectionFailed("Bad Connection Config".to_string(), e).into()
    });
    let conn_config = conn_config?;
    create_r2d2_pool(conn_config, pool_config)
}

