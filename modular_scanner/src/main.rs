use std::env;

use anyhow::Result;
use clap::{Arg, Command};

mod error;
pub use error::Error;
mod modules;
mod ports;
mod common_ports;
mod dns;
mod cli;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error>{
	
	let cli = Command::new(clap::crate_name!())
		.version(crate::version!())
		.about("Subdomain and Port Scanner with vulnerability detection capabilities.")


	// Set Concurrency limits
	let subdomains_concurrency = 100;
	let ports_concurrency = 200;

	// Start timer
	let start = Instant::now();
	println!("Starting scan for target: {}", target);

	// Setup HTTP client
	let http_timeout = Duration::from_secs(10);
	let http_client = Client::builder().timeout(http_timeout).build()?;

	// Get subdomains asynchronously
	let subdomains = subdomains::enumerate(&http_client, target).await?;

	// Scan Ports on subdomains asyncronously
	// The scan_ports function is called for each subdomain
	// The scan_ports function returns a Subdomain struct with the open ports
	let scan_result: Vec<Subdomain> = stream::iter(subdomains.into_iter())
		.map(|subdomain| ports::scan_ports(subdomain, port_size, ports_concurrency))
		.buffer_unordered(subdomains_concurrency)
		.collect()
		.await;

	// Print time taken for scan
	let scan_duration = start.elapsed();
	println!("Scan completed in {:?}", scan_duration);

	// Print results
	for subdomain in scan_result {
		println!("{}:", &subdomain.domain);
		for port in &subdomain.open_ports {
			println!("\t{}: open", port.port);
		}
		println!();
	}

	// Return Ok
	Ok(())
}
