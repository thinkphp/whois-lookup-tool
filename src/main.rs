use clap::{Parser, Subcommand};
use colored::*;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::proto::rr::RecordType;
use anyhow::Result;
use std::io::{Write, Read};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "whois-dns")]
#[command(about = "A CLI tool for WHOIS and DNS lookups")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Perform a WHOIS lookup")]
    Whois {
        #[arg(help = "Domain or IP address to lookup")]
        target: String,
    },
    #[command(about = "Perform a DNS lookup")]
    Dns {
        #[arg(help = "Domain to lookup")]
        domain: String,
        #[arg(help = "Record type (A, AAAA, MX, TXT, etc.)", default_value = "A")]
        record_type: String,
    },
}

fn create_whois_servers() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("com", "whois.verisign-grs.com", "domain "),
        ("net", "whois.verisign-grs.com", "domain "),
        ("org", "whois.pir.org", ""),
        ("edu", "whois.educause.edu", ""),
        ("it", "whois.nic.it", ""),
        ("uk", "whois.nic.uk", ""),
        ("ru", "whois.tcinet.ru", ""),
        ("de", "whois.denic.de", "-T dn "),
        ("nl", "whois.domain-registry.nl", ""),
    ]
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Whois { target } => {
            perform_whois(&target)?;
        }
        Commands::Dns { domain, record_type } => {
            perform_dns(&domain, &record_type).await?;
        }
    }

    Ok(())
}

fn get_tld(domain: &str) -> Option<&str> {
    domain.split('.').last()
}

fn perform_whois(target: &str) -> Result<()> {
    let servers = create_whois_servers();

    // First try the TLD-specific server
    if let Some(tld) = get_tld(target) {
        if let Some(&(_, server, prefix)) = servers.iter().find(|&&(t, _, _)| t == tld) {
            match query_whois_server(server, prefix, target) {
                Ok(result) => {
                    print_whois_result(server, &result);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("TLD-specific server failed: {}. Trying IANA...", e);
                }
            }
        }
    }

    // Fallback to IANA
    match query_whois_server("whois.iana.org", "", target) {
        Ok(result) => {
            print_whois_result("whois.iana.org", &result);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("WHOIS lookup failed: {}", e))
    }
}

fn query_whois_server(server: &str, prefix: &str, target: &str) -> Result<String> {
    let mut stream = TcpStream::connect((server, 43))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Send query
    let query = format!("{}{}\r\n", prefix, target);
    stream.write_all(query.as_bytes())?;

    // Read response
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    if response.trim().is_empty() {
        return Err(anyhow::anyhow!("Empty response from server"));
    }

    Ok(response)
}

fn print_whois_result(server: &str, result: &str) {
    println!("{}", "WHOIS Information:".green().bold());
    println!("{}", "-".repeat(50));
    println!("Server used: {}", server.blue());
    println!("{}", "-".repeat(50));
    println!("{}", result);
}

async fn perform_dns(domain: &str, record_type_str: &str) -> Result<()> {
    let resolver = Resolver::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
    )?;

    let record_type = match record_type_str.to_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "CNAME" => RecordType::CNAME,
        _ => return Err(anyhow::anyhow!("Unsupported record type")),
    };

    let response = resolver.lookup(domain, record_type)?;

    println!("{}", "DNS Records:".green().bold());
    println!("{}", "-".repeat(50));

    for record in response.iter() {
        match record {
            trust_dns_resolver::proto::rr::record_data::RData::A(ip) => {
                println!("A Record: {}", ip);
            }
            trust_dns_resolver::proto::rr::record_data::RData::AAAA(ip) => {
                println!("AAAA Record: {}", ip);
            }
            trust_dns_resolver::proto::rr::record_data::RData::MX(mx) => {
                println!("MX Record: {} (priority: {})", mx.exchange(), mx.preference());
            }
            trust_dns_resolver::proto::rr::record_data::RData::TXT(txt) => {
                println!("TXT Record: {}", txt.txt_data().iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<Vec<_>>()
                    .join(" "));
            }
            trust_dns_resolver::proto::rr::record_data::RData::NS(ns) => {
                println!("NS Record: {}", ns);
            }
            trust_dns_resolver::proto::rr::record_data::RData::CNAME(cname) => {
                println!("CNAME Record: {}", cname);
            }
            _ => println!("Other Record: {:?}", record),
        }
    }

    Ok(())
}
