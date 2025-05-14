/// The `Crtsh` struct provides functionality for subdomain enumeration using the crt.sh service.
/// 
/// # Overview
/// 
/// This module is part of a larger subdomain enumeration framework and is implemented as a `Module`
/// and `SubdomainModule`. It interacts with the crt.sh service to fetch subdomains associated with
/// a given target domain.
/// 
/// # Methods
/// 
/// - `new()`: Constructs a new instance of the `Crtsh` struct.
/// - `name()`: Returns the name of the module as `"subdomains/crtsh"`.
/// - `description()`: Provides a brief description of the module.
/// - `enumerate(target: &str)`: Asynchronously enumerates subdomains for the given target domain.
/// 
/// # Errors
/// 
/// The `enumerate` method returns a `Result` which may contain:
/// - A vector of valid subdomains (`Vec<String>`).
/// - An `Error` if the HTTP request or DNS resolution fails.
/// 
/// # Example Usage
/// 
/// ```rust
/// let crtsh = Crtsh::new();
/// let subdomains = crtsh.enumerate("example.com").await.unwrap();
/// for subdomain in subdomains {
///     println!("{}", subdomain);
/// }
/// ```
use crate::{
	modules::{Module, SubdomainModule},
	Error,
};
use std::collections::HashSet;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};


pub struct Crtsh {}


#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrtShEntry {
	name_value: String,
}

impl Crtsh {
	pub fn new() -> Self {
		Crtsh {}
	}
}

/// Implementation of the `Module` trait for the `Crtsh` struct.
/// 
/// This implementation provides the following functionalities:
/// 
/// - `name`: Returns the name of the module as a `String`. In this case, it is `"subdomains/crtsh"`.
/// - `description`: Returns a brief description of the module as a `String`. Here, it describes the module as
///   `"Subdomain enumeration using crt.sh"`.
/// 
/// The `Crtsh` module is designed for subdomain enumeration by leveraging the crt.sh service.
impl Module for Crtsh {
	fn name(&self) -> String {
		"subdomains/crtsh".to_string()
	}

	fn description(&self) -> String {
		"Subdomain enumeration using crt.sh".to_string()
	}
}

#[async_trait]
impl SubdomainModule for Crtsh {
	/// Asynchronously enumerates subdomains for the given target domain.
	/// 
	/// This method fetches subdomains from the crt.sh service and filters out duplicates and invalid
	/// subdomains. 
	/// 
	/// # Arguments
	/// 
	/// * `target` - A string slice representing the target domain for which to enumerate subdomains.
	/// 
	/// # Returns
	/// 
	/// A `Result` containing either:
	/// - A vector of valid subdomains (`Vec<String>`).
	/// - An `Error` if the HTTP request fails.
	async fn enumerate(&self, target: &str) -> Result<Vec<String>, Error> {
	
		// Get subdomains from crt.sh
		let res = reqwest::get(&format!("https://crt.sh/?q=%25.{}&output=json", target)).await?;

		if !res.status().is_success() {
			return Err(Error::InvalidHttpResponse(self.name()));
		}

		let entries: Vec<CrtShEntry> = match res.json().await {
			Ok(info) => info,
			Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
		};

		// Filter out duplicates and invalid subdomains
		let mut subdomains: HashSet<String> = entries
			.into_iter()
			.flat_map(|entry| {
				entry
					.name_value
					.split('\n')
					.map(|subdomain| subdomain.trim().to_string())
					.collect::<Vec<String>>()
			})
			.filter(|subdomain: &String| subdomain != target)
			.filter(|subdomain: &String| !subdomain.contains('*'))
			.collect();

		Ok(subdomains.into_iter().collect())
	}
}