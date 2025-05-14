use crate::{
	common_ports::MOST_COMMON_PORTS, 
	modules::{Port, Subdomain}
};
use std::{
	net::{SocketAddr, ToSocketAddrs},
	time::Duration,
};
use futures::{stream, StreamExt};
use tokio::net::TcpStream;

pub async fn scan_ports(mut subdomain: Subdomain, port_size: u16, concurrency: usize) -> Subdomain {
	
	let socket_addresses: Vec<SocketAddr> = format!("{}:1024", subdomain.domain)
		.to_socket_addrs()
		.expect("port scanner: Creating socket address")
		.collect();

	if socket_addresses.is_empty() {
		return subdomain;
	}

	subdomain.open_ports = stream::iter(MOST_COMMON_PORTS.into_iter().cloned())
		.take(port_size as usize)
		.map(|port| {
			let socket_address = socket_addresses[0].clone();
			async move { scan_port(socket_address, port).await }
		})
		.buffer_unordered(concurrency)
		.filter(|port|  futures::future::ready(port.is_open))
		.collect()
		.await;
	
	subdomain
}

async fn scan_port(mut socket_address: SocketAddr, port: u16) -> Port {
	let timeout = Duration::from_secs(2);
	socket_address.set_port(port);

	let is_open = matches!(
		tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await,
		Ok(Ok(_)),
	);

	Port { port, is_open, findings: Vec::new() }
}