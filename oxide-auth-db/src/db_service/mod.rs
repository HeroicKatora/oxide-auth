#[cfg(feature = "with-redis")]
pub mod redis;

#[cfg(feature = "with-redis")]
use redis::RedisDataSource;

#[cfg(feature = "with-redis")]

/// A datasource service to restore clients;
/// users can change to another database, mysql or postgresql .etc. and add corresponding implements.
/// for example: pub type DataSource = MysqslDataSource;
pub type DataSource = RedisDataSource;
