use std::{
	env,
	time::{Duration, Instant},
};
use reqwest::Client;
use futures::{stream, StreamExt};

mod error;
pub use error::Error;
mod model;
use model::Subdomain;
mod ports;
mod subdomains;
mod common_ports;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error>{
	
	// Argument Parsing
    let args: Vec<String> = env::args().collect();
	//  Check if the number of arguments is correct
	if (args.len() != 3 && args.len() != 2) || args[1] == "--help" { 
		return Err(Error::CgiUsage.into());
	}
	// first argument is the target
	let target = args[1].as_str();
	// second argument is the port size
	// if not provided or parsing fails, default to 100
	let port_size = if args.len() == 3 {
		args[2].parse::<u16>().unwrap_or(100)
	} else {
		100
	};

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
