use crate::Error;
use async_trait::async_trait;
use reqwest::Client;

mod http;
mod subdomains;


/*
Trait Declaration for modules

A module is a struct that implements the Module trait.
	The Module trait requires the following methods:
		- `name`: Returns the name of the module.
		- `description`: Returns a description of the module.

A Module can either be a HttpModule or SubdomainModule.
They are both #[async_trait]s.
	HttpModule requires the following method:
		- 'scan': Takes a reference to a HttpClient and an endpoint as &str and returns a Result<Option<HttpFinding>, Error>
	SubdomainModule requires the following method:
		- 'enumerate': Takes a reference to a domain as &str and returns a Result<Vec<String>, Error>
*/

pub trait Module {
	fn name(&self) -> String;
	fn description(&self) -> String;
}

#[async_trait]
pub trait HttpModule: Module {
	async fn scan(
		&self,
		client: &Client,
		endpoint: &str,
	) -> Result<Option<HttpFinding>, Error>;
}

#[async_trait]
pub trait SubdomainModule: Module {
	async fn enumerate(
		&self,
		domain: &str,
	) -> Result<Vec<String>, Error>;
}

/*
Struct / Enum Declaration for modules

Port is a struct that represents a port.
It has two fields:
	- `port`: The port number.
	- `is_open`: A boolean indicating if the port is open or not.

Subdomain is a struct that represents a subdomain.
It has two fields:
	- `domain`: The subdomain name.
	- `open_ports`: A vector of Port structs representing the open ports for the subdomain.

HttpFinding is an enum that represents a finding from an HTTP module.
*/

#[derive(Debug, Clone)]
pub struct Port {
	pub port: u16,
	pub is_open: bool,
	pub findings: Vec<HttpFinding>,
}

#[derive(Debug, Clone)]
pub struct Subdomain {
	pub domain: String,
	pub open_ports: Vec<Port>,
}

#[derive(Debug, Clone)]
pub enum HttpFinding {
	DirectoryListingDisclosure(String),
	DotEnvDisclosure(String),
	DsStoreDisclosure(String),
	TraefikDashboardUnauthenticatedAccess(String),
	PrometheusDashboardUnauthenticatedAccess(String),
	KibanaUnauthenticatedAccess(String),
	GitlabOpenRegistrations(String),
	GitHeadDisclosure(String),
	GitDirectoryDisclosure(String),
	GitConfigDisclosure(String),
	EtcdUnauthenticatedAccess(String),
	Cve2017_9506(String),
	Cve2018_7600(String),
	ElasticsearchUnauthenticatedAccess(String),
}

/*
Function definitions for modules
	- `get_http_modules`: Returns a vector of all HTTP modules.
	- `get_subdomain_modules`: Returns a vector of all subdomain modules.
*/

pub fn get_http_modules() -> Vec<Box<dyn HttpModule>> {
	vec![
		// Box::new(http::DirectoryListingDisclosure::new()),
		// Box::new(http::DotEnvDisclosure::new()),
		// Box::new(http::DsStoreDisclosure::new()),
		// Box::new(http::TraefikDashboardUnauthenticatedAccess::new()),
		// Box::new(http::PrometheusDashboardUnauthenticatedAccess::new()),
		// Box::new(http::KibanaUnauthenticatedAccess::new()),
		// Box::new(http::GitlabOpenRegistrations::new()),
		// Box::new(http::GitHeadDisclosure::new()),
		// Box::new(http::GitDirectoryDisclosure::new()),
		// Box::new(http::GitConfigDisclosure::new()),
		// Box::new(http::EtcdUnauthenticatedAccess::new()),
		// Box::new(http::Cve2017_9506::new()),
		// Box::new(http::Cve2018_7600::new()),
		// Box::new(http::ElasticsearchUnauthenticatedAccess::new()),
	]
}

pub fn get_subdomain_modules() -> Vec<Box<dyn SubdomainModule>> {
	vec![
		Box::new(subdomains::Crtsh::new()),
		Box::new(subdomains::WebArchive::new()),
	]
}