use thiserror::Error;

/// Custom error types for the test auditor
#[derive(Error, Debug)]
pub enum AuditorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Path validation failed: {message}")]
    PathValidation { message: String },
    
    #[error("Configuration error: {0}")]
    Config(#[from] toml::de::Error),
    
    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("File too large: {path} ({size} bytes, max {max_size} bytes)")]
    FileTooLarge { path: String, size: u64, max_size: u64 },
    
    #[error("Canonicalization failed for path '{path}': {source}")]
    Canonicalization { path: String, source: std::io::Error },
    
    #[error("Path traversal detected: '{path}' is outside root '{root}'")]
    PathTraversal { path: String, root: String },
    
    #[error("Parallel processing error: {message}")]
    ParallelProcessing { message: String },
    
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),
    
    #[error("XML serialization error: {0}")]
    XmlSerialization(#[from] quick_xml::DeError),
    
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },
}

/// Result type alias for auditor operations
pub type AuditorResult<T> = Result<T, AuditorError>;