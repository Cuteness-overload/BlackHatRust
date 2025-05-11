use crate::{
	model::{Subdomain, CrtShEntry},
	Error,
};
use reqwest::Client;
use std::{collections::HashSet, time::Duration};
use futures::{stream, StreamExt};
use trust_dns_resolver::{
	AsyncResolver,
	config::{ResolverConfig, ResolverOpts},
	name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
};

// Create a type alias for the DNS resolver
// This is a generic connection provider for the Tokio runtime
// The Tokio runtime is an asynchronous runtime for Rust
type DnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub async fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Subdomain>, Error> {
	
	// Get subdomains from crt.sh
	let entries: Vec<CrtShEntry> = http_client
		.get(&format!("https://crt.sh/?q=%25.{}&output=json", target))
		.send()
		.await?
		.json()
		.await?;

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

	subdomains.insert(target.to_string());
	
	// Create Asyncronous DNS Resolver
	let dns_resolver = AsyncResolver::tokio(
		ResolverConfig::default(),
		{
			let mut opts  = ResolverOpts::default();
			opts.timeout = Duration::from_secs(4);
			opts
		},
	)
	.expect("subdomain resolver: building  DNS client");

	// Check if subdomains resolve to an IP address
	let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
		.map(|domain| Subdomain {
			domain,
			open_ports: Vec::new(),
		})
		.filter_map(|subdomain| {
			let dns_resolver = dns_resolver.clone();
			async move {
				if resolves(&dns_resolver, &subdomain).await {
					Some(subdomain)
				} else {
					None
				}
			}
		})
		.collect()
		.await;

	Ok(subdomains)
}

async fn resolves(dns_resolver: &DnsResolver, domain: &Subdomain) -> bool {
	dns_resolver.lookup_ip(domain.domain.as_str()).await.is_ok()
}