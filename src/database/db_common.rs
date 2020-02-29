use std::env;
use std::path::Path;

use tokio_postgres::Config as TokioConfig;
use postgres::Config as PostgresConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) dbname: String,
    pub(crate) user: String,
    pub(crate) password: String,
}

impl ConnectionConfig {
    pub fn new(host: String, port: u16, dbname: String, user: String, password: String) -> Self {
        Self { host, port, dbname, user, password }
    }
}


impl From<ConnectionConfig> for TokioConfig {
    fn from(params: ConnectionConfig) -> Self {
        let mut config = TokioConfig::default();
        config.host(params.host.as_str());
        config.port(params.port);
        config.dbname(params.dbname.as_str());
        config.user(params.user.as_str());
        config.password(params.password.as_str());
        config
    }
}

impl From<ConnectionConfig> for PostgresConfig {
    fn from(params: ConnectionConfig) -> Self {
        let mut config = TokioConfig::default();
        config.host(params.host.as_str());
        config.port(params.port);
        config.dbname(params.dbname.as_str());
        config.user(params.user.as_str());
        config.password(params.password.as_str());
        PostgresConfig::from(config)
    }
}


#[derive(Debug, PartialEq)]
pub struct PoolConfig {
    pub(crate) min_size: u16,
    pub(crate) max_size: u16,
}

impl PoolConfig {
    pub fn new(min_size: u16, max_size: u16) -> Self {
        Self { min_size, max_size }
    }
}

pub fn pg_pool_config_from_env() -> Result<PoolConfig, String> {
    let mut config = PoolConfig { min_size: 8, max_size: 16 };
    if let Ok(min_size_string) = env::var("POOL_MIN_SIZE") {
        config.min_size = min_size_string.parse::<u16>()
            .map_err(|_| format!("Invalid POOL_MIN_SIZE: {}", min_size_string))?;
    }
    if let Ok(max_size_string) = env::var("POOL_MAX_SIZE") {
        config.max_size = max_size_string.parse::<u16>()
            .map_err(|_| format!("Invalid POOL_MIN_SIZE: {}", max_size_string))?;
    }
    Ok(config)
}

pub fn pg_connection_config_from_env() -> Result<ConnectionConfig, String> {
    let host = if let Ok(host) = env::var("PG_HOST") {
        host
    } else {
        if Path::new("/run/postgresql").exists() {
            "/run/postgresql".to_string()
        } else {
            "/tmp".to_string()
        }
    };
    let port = if let Ok(port_string) = env::var("PG_PORT") {
        let port = port_string.parse::<u16>()
            .map_err(|_| format!("Invalid PG_PORT: {}", port_string))?;
        port
    } else {
        return Err("Missing PG_PORT. Fallback to USER failed as well.".into());
    };
    let user = if let Ok(user) = env::var("PG_USER") {
        user
    } else if let Ok(user) = env::var("USER") {
        user
    } else {
        return Err("Missing PG_USER. Fallback to USER failed as well.".into());
    };
    let password = if let Ok(password) = env::var("PG_PASSWORD") {
        password
    } else {
        return Err("Missing PG_PASSWORD.".into());
    };
    let dbname = if let Ok(dbname) = env::var("PG_DBNAME") {
        dbname
    } else {
        return Err("Missing PG_DBNAME.".into());
    };
    Ok(ConnectionConfig::new(host, port, dbname, user, password))
}

#[cfg(test)]
mod db_common {
    use super::*;

    #[test]
    fn pg_pool_config_from_env_validation() {
        dotenv::dotenv().ok();
        let computed = pg_pool_config_from_env().unwrap();
        let expected = PoolConfig::new(4, 16);
        assert_eq!(computed, expected);
    }

    #[test]
    fn pg_connection_config_from_env_validation() {
        dotenv::dotenv().ok();
        let computed = pg_connection_config_from_env().unwrap();
        let expected = ConnectionConfig::new(
            "localhost".to_string(), 5432u16, "demodb".to_string(), "postgres".to_string(), "postgres".to_string()
        );
        assert_eq!(computed, expected);
    }
}
