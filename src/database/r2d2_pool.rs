use failure::Error;

use postgres::NoTls;
use postgres::Config;

use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use crate::database::db_common::{ConnectionConfig, PoolConfig};
use crate::database::db_pool::create_pool;


pub(crate) fn manager(conn_config: ConnectionConfig) -> PostgresConnectionManager<NoTls> {
    let conn_config = Config::from(conn_config);
    let tls_connector = postgres::NoTls;
    let r2d2_manager = PostgresConnectionManager::<NoTls>::new(
        conn_config,
        tls_connector,
    );
    r2d2_manager
}

pub fn create_r2d2_pool(conn_config: ConnectionConfig, pool_config: PoolConfig) -> Result<Pool<PostgresConnectionManager<NoTls>>, Error> {
    let manager = manager(conn_config);
    create_pool(manager, pool_config)
}