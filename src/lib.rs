use std::error::Error;
use std::fmt;

pub mod btf_index;
pub mod c_dumper;
pub mod relocator;
pub mod types;

#[derive(Debug)]
pub struct BtfError {
    details: String,
}

impl BtfError {
    pub fn new(msg: &str) -> BtfError {
        BtfError {
            details: msg.to_string(),
        }
    }
    pub fn new_owned(msg: String) -> BtfError {
        BtfError { details: msg }
    }
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for BtfError {
    fn description(&self) -> &str {
        &self.details
    }
}

pub type BtfResult<T> = Result<T, Box<dyn Error>>;

pub fn btf_error<T>(msg: String) -> BtfResult<T> {
    Err(Box::new(BtfError::new_owned(msg)))
}
