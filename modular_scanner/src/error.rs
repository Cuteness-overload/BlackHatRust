use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("usage: simple_scanner <domain.com> [<top_n_ports>]
		Scan a domain for open ports.
		Options:
			<domain.com>  The domain to scan.
			<top_n_ports> The number of ports to scan (optional).
			--help        Show this help message.")]
	CgiUsage,
	#[error("Reqwest: {0}")]
	Reqwest(String),
	#[error("Invalid Http Response: {0}")]
	InvalidHttpResponse(String),
	#[error("Tokio join error: {0}")]
	TokioJoinError(String),
}

impl std::convert::From<reqwest::Error> for Error {
	fn from(err: reqwest::Error) -> Self {
		Error::Reqwest(err.to_string())
	}
}

impl std::convert::From<tokio::task::JoinError> for Error {
	fn from(err: tokio::task::JoinError) -> Self {
		Error::TokioJoinError(err.to_string())
	}
}