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
}

impl std::convert::From<reqwest::Error> for Error {
	fn from(err: reqwest::Error) -> Self {
		Error::Reqwest(err.to_string())
	}
}