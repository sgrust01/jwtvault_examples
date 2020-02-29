use failure::Error;

use r2d2::{ManageConnection, Pool};

use crate::database::db_common::PoolConfig;
use crate::database::errors::DatabaseErrors::PoolCreationFailed;

pub(crate) fn create_pool<M>(manager: M, pool_config: PoolConfig) -> Result<Pool<M>, Error>
    where M: ManageConnection
{
    let builder = Pool::<M>::builder();
    builder
        .min_idle(Some(pool_config.min_size.into()))
        .max_size(pool_config.max_size.into())
        .build(manager).map_err(|e| {
        let reason = e.to_string();
        let msg = "Unable to create pool".to_string();
        PoolCreationFailed(msg, reason).into()
    })
}