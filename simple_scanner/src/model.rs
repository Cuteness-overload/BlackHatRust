use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CrtShEntry {
	pub name_value: String,
}

#[derive(Debug, Clone)]
pub struct Port {
	pub port: u16,
	pub is_open: bool,
}

#[derive(Debug, Clone)]
pub struct Subdomain {
	pub domain: String,
	pub open_ports: Vec<Port>,
}