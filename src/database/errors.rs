use failure::Fail;

#[derive(Debug, Fail)]
pub enum DatabaseErrors {
    #[fail(display = "{}. Reason: {}", 0, 1)]
    ConnectionFailed(String, String),
    #[fail(display = "{}. Reason: {}", 0, 1)]
    PoolCreationFailed(String, String),
}
