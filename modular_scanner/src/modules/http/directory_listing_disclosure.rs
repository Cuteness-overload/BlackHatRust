use crate::{
	modules::{HttpFinding, HttpModule, Module},
	Error,
};
use async_trait::async_trait;
use reqwest::Client;
use regex::Regex;

pub struct DirectoryListingDisclosure {
	pub dir_regex: Regex,
}

impl DirectoryListingDisclosure {
	pub fn new() -> Self {
		let dir_regex = Regex::new(r"<title>Index of .*</title>").unwrap();
		Self { dir_regex }
	}

	async fn is_directory_listing(&self, body: String) -> Result<bool, Error> {
		let dir_regex = self.dir_regex.clone();
		let is_dir = tokio::task::spawn_blocking(move || {
			dir_regex.is_match(&body)
		}).await?;
		Ok(is_dir)
	}
}

impl Module for DirectoryListingDisclosure {
	fn name(&self) -> String {
		"http/directory_listing".to_string()
	}

	fn description(&self) -> String {
		"Checks for directory listing, which can potentially leak info".to_string()
	}
}

#[async_trait]
impl HttpModule for DirectoryListingDisclosure {
	async fn scan(&self, client: &Client, endpoint: &str) -> Result<Option<HttpFinding>, Error> {
		let url = format!("{}/", endpoint);
		let response = client.get(&url).send().await?;

		if !response.status().is_success() {
			return Ok(None);
		}

		let body = response.text().await?;
		if self.is_directory_listing(body).await? {
			return Ok(Some(HttpFinding::DirectoryListingDisclosure(url)));
		}
		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use super::DirectoryListingDisclosure;
	use crate::modules::HttpModule;

	#[tokio::test]
	async fn is_directory_listing_1() {
		let module = DirectoryListingDisclosure::new();
		let body = "<html><head><title>Index of /</title></head><body></body></html>";
		assert!(module.is_directory_listing(body.to_string()).await.unwrap());
	}

	#[tokio::test]
	async fn is_directory_listing_2() {
		let module = DirectoryListingDisclosure::new();
		let body = "Content <title>Index of /foo</title>";
		assert!(module.is_directory_listing(body.to_string()).await.unwrap());
	}

	#[tokio::test]
	async fn is_not_directory_listing_1() {
		let module = DirectoryListingDisclosure::new();
		let body = "<html><head><title>Not a directory listing</title></head><body></body></html>";
		assert!(!module.is_directory_listing(body.to_string()).await.unwrap());
	}

	#[tokio::test]
	async fn is_not_directory_listing_2() {
		let module = DirectoryListingDisclosure::new();
		let body = "Content <title>Not a Index of</title>";
		assert!(!module.is_directory_listing(body.to_string()).await.unwrap());
	}

	#[tokio::test]
	async fn scan() {
		let module = DirectoryListingDisclosure::new();
		let client = reqwest::Client::new();
		let endpoint = "http://example.com";
		let result = module.scan(&client, endpoint).await;
		assert!(result.is_ok());
	}

}