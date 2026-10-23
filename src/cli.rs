use std::{
    io::{self, Write},
    time::Duration,
};

use clap::{Parser, Subcommand};
use rand::seq::SliceRandom;
use tracing::{info, warn};

use crate::{
    error::{Error, Result},
    pptp::control::{establish, ControlConnectOptions},
    session::{self, SessionOptions},
};

#[derive(Debug, Parser)]
#[command(
    name = "haiip",
    version,
    about = "독립형 Rust Hai-IP PPTP 클라이언트",
    long_about = "PPTP 제어, Enhanced GRE, PPP, MS-CHAPv2, IPCP와 Linux TUN을 직접 처리하는 Hai-IP 클라이언트입니다. 기본 auto 모드는 Hai-IP 서버 풀에서 연결 가능한 엔드포인트를 선택합니다."
)]
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
        #[arg(long, default_value = "auto")]
        server: String,
        #[arg(long, default_value_t = 1723)]
        port: u16,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
        #[arg(
            long,
            conflicts_with = "username_env",
            help = "Hai-IP 아이디와 VPN 번호를 결합한 사용자명 (예: user@1)"
        )]
        username: Option<String>,
        #[arg(long, conflicts_with = "username")]
        username_env: Option<String>,
        #[arg(long, env = "HAIIP_PASSWORD_ENV")]
        password_env: Option<String>,
        #[arg(long, default_value = "haiip0")]
        tun_name: String,
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        /// LCP Echo-Request 간격(초). 0이면 보내지 않습니다.
        #[arg(long, default_value_t = session::DEFAULT_ECHO_INTERVAL.as_secs())]
        echo_interval_seconds: u64,
        /// 이 시간(초) 동안 GRE 수신이 전혀 없으면 세션을 끊고 재연결합니다. 0이면 비활성화.
        #[arg(long, default_value_t = session::DEFAULT_PEER_TIMEOUT.as_secs())]
        peer_timeout_seconds: u64,
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
    /// Show client capabilities and credential handling.
    About,
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
            echo_interval_seconds,
            peer_timeout_seconds,
            control_only,
        } => {
            let servers = selected_servers(&server);
            if control_only {
                let mut last_error = None;
                for server in servers {
                    match establish(&ControlConnectOptions {
                        server: server.clone(),
                        port,
                        timeout: Duration::from_secs(timeout_seconds),
                    })
                    .await
                    {
                        Ok(established) => {
                            println!(
                                "PPTP control established: peer={}, version=0x{:04x}, firmware={}",
                                established.peer,
                                established.server.protocol_version,
                                established.server.firmware_revision
                            );
                            return Ok(());
                        }
                        Err(error) => {
                            warn!(%server, %error, "PPTP control server unavailable; trying next candidate");
                            last_error = Some(error);
                        }
                    }
                }
                Err(last_error.expect("server candidate list is never empty"))
            } else {
                let username = resolve_username(username, username_env)?;
                let password = resolve_password(password_env)?;
                let mut last_error = None;
                for server in servers {
                    info!(%server, "attempting Hai-IP connection");
                    match session::connect(SessionOptions {
                        server: server.clone(),
                        port,
                        username: username.clone(),
                        password: password.clone(),
                        tun_name: tun_name.clone(),
                        mtu,
                        echo_interval: Duration::from_secs(echo_interval_seconds),
                        peer_timeout: Duration::from_secs(peer_timeout_seconds),
                    })
                    .await
                    {
                        Ok(()) => return Ok(()),
                        Err(error) => {
                            warn!(%server, %error, "Hai-IP server attempt failed; trying next candidate");
                            last_error = Some(error);
                        }
                    }
                }
                Err(last_error.expect("server candidate list is never empty"))
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
        Command::About => {
            println!(
                "Hai-IP Client — 독립형 Rust PPTP 구현\n\nPPTP 제어, Enhanced GRE, PPP, MS-CHAPv2, IPCP와 Linux TUN을 직접 처리합니다. 기본 auto 모드는 Hai-IP 서버 풀에서 연결 가능한 엔드포인트를 선택하며, 서비스 인증 정보는 root 전용 환경 파일에서만 읽습니다.\n\n설치  sudo ./scripts/install.sh --username <사용자명> --password <비밀번호>\n삭제  sudo ./scripts/uninstall.sh"
            );
            Ok(())
        }
        Command::Disconnect => Err(Error::NotImplemented("disconnect supervisor")),
        Command::Status => Err(Error::NotImplemented("status supervisor")),
        Command::RouteStatus => Err(Error::NotImplemented("route management")),
    }
}

fn selected_servers(server: &str) -> Vec<String> {
    if server != "auto" {
        return vec![server.to_owned()];
    }
    let mut servers = (1..=8)
        .map(|index| format!("hai-ip{index}.haion.net"))
        .collect::<Vec<_>>();
    servers.shuffle(&mut rand::thread_rng());
    servers
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

#[cfg(test)]
mod tests {
    use super::selected_servers;

    #[test]
    fn auto_server_selection_contains_every_hai_ip_host_once() {
        let mut servers = selected_servers("auto");
        servers.sort();
        assert_eq!(
            servers,
            (1..=8)
                .map(|index| format!("hai-ip{index}.haion.net"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn explicit_server_selection_does_not_change_the_target() {
        assert_eq!(selected_servers("vpn.example.test"), ["vpn.example.test"]);
    }
}
