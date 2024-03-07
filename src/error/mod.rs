#[derive(thiserror::Error, Debug)]
pub enum MyError {
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),
    // #[error("Parse error: {0}")]
    // ParseError(#[from] std::num::ParseIntError),
}

pub type MyResult<T> = std::result::Result<T, MyError>;
