use std::env;

use anyhow::Result;
use clap::{Arg, Command, value_parser};

mod error;
pub use error::Error;
mod modules;
mod ports;
mod common_ports;
mod dns;
mod cli;

fn main() -> Result<()>{
	

	
	let cli = Command::new(clap::crate_name!())
		.version(clap::crate_version!())
		.about("Subdomain and Port Scanner with vulnerability detection capabilities.")
		.subcommand(Command::new("modules").about("List all modules"))
		.subcommand(Command::new("scan")
			.about("Scan a target")
			.arg(Arg::new("target")
				.help("The domain name to scan")
				.required(true)
				.short('d')
				.long("domain")
				.takes_value(true)
			)
			.arg(Arg::new("ports")
				.help("Number of ports to scan")
				.short('p')
				.long("ports")
				.default_value("100")
				.value_parser(value_parser!(u16))
			)
			.arg(Arg::new("vuln")
				.help("Scan for vulnerabilities")
				.short('v')
				.long("vuln")
				.takes_value(false)
			)
			.arg(Arg::new("enumerate")
				.help("Enumerate subdomains")
				.short('e')
				.long("enumerate")
				.takes_value(false)
			)
		)
		.arg_required_else_help(true)
		.get_matches();
	
	// Set up logging
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
		.format(|buf, record| {
			println!("{} [!] {}", buf.timestamp(), record.args());
			Ok(())
		})
		.init();
	log::info!("Starting modular scanner...\n");
	
	if let Some(_) = cli.subcommand_matches("modules") {
		cli::modules();
	} else if let Some(matches) = cli.subcommand_matches("scan") {
		let target = matches.get_one::<String>("target").unwrap();
		let ports: u16 = matches.get_one::<u16>("ports").unwrap().clone();
		let enumerate = matches.is_present("enumerate");
		let vuln = matches.is_present("vuln");
		cli::scan(target, ports, enumerate, vuln)?;
	}

	// Return Ok
	Ok(())
}
