use std::{
    io::{self, Write},
    time::Duration,
};

use clap::{Parser, Subcommand};

use crate::{
    error::{Error, Result},
    pptp::control::{establish, ControlConnectOptions},
    session::{self, SessionOptions},
};

#[derive(Debug, Parser)]
#[command(name = "haiip", version, about = "Standalone Hai-IP PPTP client")]
pub struct Cli {
    #[arg(long, global = true, default_value = "info", env = "RUST_LOG")]
    pub log_level: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Open TCP/1723 and complete the PPTP Start-Control exchange.
    Connect {
        #[arg(long, default_value = "haiip2.haion.net")]
        server: String,
        #[arg(long, default_value_t = 1723)]
        port: u16,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
        #[arg(long, conflicts_with = "username_env")]
        username: Option<String>,
        #[arg(long, conflicts_with = "username")]
        username_env: Option<String>,
        #[arg(long, env = "HAIIP_PASSWORD_ENV")]
        password_env: Option<String>,
        #[arg(long, default_value = "haiip0")]
        tun_name: String,
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        #[arg(long)]
        control_only: bool,
    },
    /// Disconnect the managed background session (supervisor milestone).
    Disconnect,
    /// Show the managed connection state (supervisor milestone).
    Status,
    /// Inspect local support and protocol implementation status.
    Inspect,
    /// Show route snapshot and tunnel routes (routing milestone).
    RouteStatus,
    /// Print packet capture guidance.
    CaptureInfo,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Connect {
            server,
            port,
            timeout_seconds,
            username,
            username_env,
            password_env,
            tun_name,
            mtu,
            control_only,
        } => {
            if control_only {
                let established = establish(&ControlConnectOptions {
                    server,
                    port,
                    timeout: Duration::from_secs(timeout_seconds),
                })
                .await?;
                println!(
                    "PPTP control established: peer={}, version=0x{:04x}, firmware={}",
                    established.peer,
                    established.server.protocol_version,
                    established.server.firmware_revision
                );
                Ok(())
            } else {
                let username = resolve_username(username, username_env)?;
                let password = resolve_password(password_env)?;
                session::connect(SessionOptions {
                    server,
                    port,
                    username,
                    password,
                    tun_name,
                    mtu,
                })
                .await
            }
        }
        Command::Inspect => {
            println!(
                "PPTP control: ready\nEnhanced GRE: ready\nLCP/MS-CHAPv2/IPCP: ready\nLinux TUN: ready\nRoute mode: interface-only"
            );
            Ok(())
        }
        Command::CaptureInfo => {
            println!("sudo tcpdump -ni any -w haiip.pcap 'tcp port 1723 or proto 47'");
            Ok(())
        }
        Command::Disconnect => Err(Error::NotImplemented("disconnect supervisor")),
        Command::Status => Err(Error::NotImplemented("status supervisor")),
        Command::RouteStatus => Err(Error::NotImplemented("route management")),
    }
}

fn resolve_username(username: Option<String>, username_env: Option<String>) -> Result<String> {
    match (username, username_env) {
        (Some(username), None) => Ok(username),
        (None, Some(variable)) => {
            std::env::var(&variable).map_err(|_| Error::MissingSecret(variable))
        }
        (None, None) => prompt("Hai-IP 사용자명: "),
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting credential options"),
    }
}

fn resolve_password(password_env: Option<String>) -> Result<String> {
    match password_env {
        Some(variable) => std::env::var(&variable).map_err(|_| Error::MissingSecret(variable)),
        None => {
            print!("Hai-IP 비밀번호: ");
            io::stdout().flush()?;
            rpassword::read_password().map_err(Error::from)
        }
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::Ppp("사용자명은 비어 있을 수 없습니다".into()));
    }
    Ok(value)
}
