use crate::{
	modules,
	modules::{HttpModule, Subdomain},
	Error,
	dns,
	ports,
};
use reqwest::Client;
use std::time::{Duration, Instant};
use futures::{stream, StreamExt};
use std::collections::HashSet;

pub fn modules() {
	let http_modules = modules::get_http_modules();
	let subdomain_modules = modules::get_subdomain_modules();

	println!("Subdomain modules");
	for module in subdomain_modules {
		println!("\t- {}: {}", module.name(), module.description());
	}

	println!("HTTP modules");
	for module in http_modules {
		println!("\t- {}: {}", module.name(), module.description());
	}
}

pub fn scan(target: &str, ports: u16, enumerate: bool, vuln: bool) -> Result<(), Error> {
	
	// Set up tokio async runtime
	let rt = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.expect("Building tokio's runtime");

	// Set variables
	let dns_resolver = dns::new_resolver();
	let subdomain_modules = modules::get_subdomain_modules();
	let http_client = Client::builder().timeout(Duration::from_secs(8)).build()?;
	// Set concurrency limits
	let subdomain_concurrency = 20;
	let dns_concurrency = 100;
	let port_concurrency = 200;
	let vuln_concurrency = 20;

	let scan_start = Instant::now();


	rt.block_on(async move {

		let subdomains: Vec<Subdomain>;
		
		if enumerate {
			// Get subdomains
			log::info!("Started subdomain enumeration for {}", target);
			
			let mut subs: Vec<String> = stream::iter(subdomain_modules.into_iter())
				.map(|module| async move {
					match module.enumerate(target).await {
						Ok(new_subdomains) => Some(new_subdomains),
						Err(err) => { 
							log::error!("{}: {}", module.name(), err);
							None
						}
					}
				})
				.buffer_unordered(subdomain_concurrency)
				.filter_map(|subdomain| async move { subdomain })
				.collect::<Vec<Vec<String>>>()
				.await
				.into_iter()
				.flatten()
				.collect();
			
			subs.push(target.to_string());		
			
			// Remove duplicates via Hashset
			// Ensure all are subdomains of the target
			subdomains = HashSet::<String>::from_iter(subs.into_iter())
				.into_iter()
				.filter(|domain| domain.contains(target))
				.map(|domain| Subdomain {
					domain,
					open_ports: vec![],
				})
				.collect();

			log::info!("Found {} unique subdomains\n", subdomains.len());

		} else {
			// If not enumerating, use the target as the only subdomain
			subdomains = vec![Subdomain { domain: target.to_string(), open_ports: vec![] }];
		}

		log::info!("Started DNS resolution");

		// Resolve subdomains
		let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
			.map(|domain| dns::resolves(&dns_resolver, domain))
			.buffer_unordered(dns_concurrency)
			.filter_map(|domain| async move { domain })
			.collect()
			.await;

		log::info!("Resolved {} subdomains\n", subdomains.len());

		// Scan ports
		log::info!("Started port scan");
		
		let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
			.map(|domain| {
				log::info!("\tScanning {}", domain.domain);
				ports::scan_ports(domain, ports, port_concurrency)
			})
			.buffer_unordered(3)
			.collect()
			.await;

		println!();
		log::info!("Port scan completed
			 Found {} open ports\n", subdomains.iter().fold(0, |acc, subdomain| acc + subdomain.open_ports.len()));
		
		for subdomain in &subdomains {
			println!("{}:", subdomain.domain);
			if subdomain.open_ports.is_empty() {
				println!("\tNo open ports");
				continue;
			}
			for port in &subdomain.open_ports {
				println!("\t- Port {}", port.port);
			}
		}

		if vuln {
			// Scan for vulnerabilities via http modules
			log::info!("Started vulnerability scan");

			let mut targets: Vec<(Box<dyn HttpModule>, String)> = vec![];
			for subdomain in subdomains {
				for port in subdomain.open_ports {
					let http_modules = modules::get_http_modules();
					for module in http_modules {
						let target = format!("http://{}:{}", &subdomain.domain, port.port);
						targets.push((module, target));
					}
				}
			}

			stream::iter(targets.into_iter())
				.for_each_concurrent(vuln_concurrency,|(module, target)| {
					let http_client = http_client.clone();
					async move {
						match module.scan(&http_client, &target).await {
							Ok(Some(finding)) => println!("{:?}", &finding),
							Ok(None) => {}
							Err(err) => log::debug!("Error: {}", err),
						};
					}
				})
				.await;
		}

	});

	log::info!("Scan completed in {:?}", scan_start.elapsed());

	Ok(())
}