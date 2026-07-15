use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum OsSenseError {
    Io(String),
    Parse(String),
    Storage(String),
    Command(String),
}

pub type Result<T> = std::result::Result<T, OsSenseError>;

impl Display for OsSenseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::Parse(message) => write!(f, "parse error: {message}"),
            Self::Storage(message) => write!(f, "storage error: {message}"),
            Self::Command(message) => write!(f, "command error: {message}"),
        }
    }
}

impl std::error::Error for OsSenseError {}

impl From<std::io::Error> for OsSenseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<rusqlite::Error> for OsSenseError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<serde_json::Error> for OsSenseError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(value.to_string())
    }
}
