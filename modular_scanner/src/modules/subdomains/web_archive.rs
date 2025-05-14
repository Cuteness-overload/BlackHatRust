use crate::{
	modules::{Module, SubdomainModule},
	Error,
};
use std::collections::HashSet;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

pub struct WebArchive {}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WebArchiveResponse(Vec<Vec<String>>);

impl WebArchive {
	pub fn new() -> Self {
		WebArchive {}
	}
}

/// Implementation of the `Module` trait for the `WebArchive` struct.
impl Module for WebArchive {
	fn name(&self) -> String {
		"subdomains/web_archive".to_string()
	}

	fn description(&self) -> String {
		"Subdomain enumeration using web.archive.org".to_string()
	}
}

#[async_trait]
impl SubdomainModule for WebArchive {
	async fn enumerate(&self, target: &str) -> Result<Vec<String>, Error> {
		let url = format!("https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&collapse=urlkey&url={}&output=json", target);
		let res = reqwest::get(&url).await?;

		if !res.status().is_success() {
			return Err(Error::InvalidHttpResponse(self.name()));
		}

		let web_archive_urls: WebArchiveResponse = match res.json().await {
			Ok(info) => info,
			Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
		};

		let subdomains: HashSet<String> = web_archive_urls
			.0
			.into_iter()
			.flatten()
			.filter(|url| url != "original")
			.filter_map(|url| {
				Url::parse(&url)
					.map_err(|err| {
						log::error!("{}: error parsing url: {}: {}", self.name(), url, err);
						err
					})
					.ok()
			})
			.filter_map(|url| url.host_str().map(|host| host.to_string()))
			.collect();

		Ok(subdomains.into_iter().collect())
	}
}