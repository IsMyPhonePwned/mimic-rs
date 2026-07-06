use thiserror::Error;

#[derive(Error, Debug)]
pub enum MimicError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("signature database error: {0}")]
    SignatureDb(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("engine error: {0}")]
    Engine(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MimicError>;
