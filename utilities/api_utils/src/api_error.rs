// utilities\api_utils\src\api_error.rs
use std::fmt;
use thiserror::Error;
use serde::{Serialize, Deserialize};

/// Trait for standardizing API errors across different backends
pub trait APIErrorTrait: fmt::Display + fmt::Debug + Send + Sync {
    fn error_code(&self) -> u16;  // HTTP Status Code or equivalent
    fn error_message(&self) -> String;
}

/// Enum defining generic API errors
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum GenericAPIError {
    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Internal Server Error: {0}")]
    InternalError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),
}

impl APIErrorTrait for GenericAPIError {
    fn error_code(&self) -> u16 {
        match self {
            GenericAPIError::BadRequest(_) => 400,
            GenericAPIError::Unauthorized(_) => 401,
            GenericAPIError::Forbidden(_) => 403,
            GenericAPIError::NotFound(_) => 404,
            GenericAPIError::InternalError(_) => 500,
            GenericAPIError::Timeout(_) => 504,
            GenericAPIError::ServiceUnavailable(_) => 503,
        }
    }

    fn error_message(&self) -> String {
        format!("{}", self)
    }
}
