use crate::modules::Subdomain;
use std::{sync::Arc, time::Duration};
use trust_dns_resolver::{
	config::{ResolverConfig, ResolverOpts},
	AsyncResolver,
	name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
};

pub type Resolver = Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>;


// Check if the domain resolves using DNS
pub async fn resolves(dns_resolver: &Resolver, domain: Subdomain) -> Option<Subdomain> {
	if dns_resolver.lookup_ip(domain.domain.as_str()).await.is_ok() {
		return Some(domain);
	}
	None
}

// Create a new DNS resolver
pub fn new_resolver() -> Resolver {
	let resolver = AsyncResolver::tokio(
		ResolverConfig::default(),
		{
			let mut opts  = ResolverOpts::default();
			opts.timeout = Duration::from_secs(4);
			opts
		},
	)
	.expect("dns/resolver: building DNS client");
	
	Arc::new(resolver)
}