use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    process::{Command, Stdio},
};

use tokio::io::unix::AsyncFd;
use tracing::warn;

use crate::error::{Error, Result};

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const ROUTE_TABLE_START: u32 = 20_000;
const ROUTE_TABLE_END: u32 = 30_000;

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    pub name: String,
    local: Ipv4Addr,
    route_policy: RoutePolicy,
}

impl TunDevice {
    pub fn create(name: &str, local: Ipv4Addr, _peer: Ipv4Addr, mtu: u16) -> Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(Error::NetworkConfiguration(
                "invalid TUN interface name".into(),
            ));
        }
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut request = IfReq::default();
        for (target, source) in request.name.iter_mut().zip(name.as_bytes()) {
            *target = *source as libc::c_char;
        }
        request.flags = IFF_TUN | IFF_NO_PI;
        if unsafe { libc::ioctl(device.as_raw_fd(), TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Adding a point-to-point peer here creates a host route to that peer.
        // Hai-IP assigns the PPTP endpoint itself as the IPCP peer, so that route
        // would capture this process's raw GRE packets and feed them back through
        // the TUN device. Configure only the client address; route selection is
        // deliberately managed separately from the transport session.
        let address_arguments = tunnel_address_arguments(local, name);
        run_ip(
            &address_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        run_ip(&["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])?;
        let fd: OwnedFd = device.into();
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let fd = AsyncFd::new(fd)?;
        let route_policy = configure_route_policy(local, name)?;
        Ok(Self {
            fd,
            name: name.to_owned(),
            local,
            route_policy,
        })
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| {
                let length = unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if length < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(length as usize)
                }
            }) {
                Ok(result) => return result.map_err(Error::from),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, packet: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < packet.len() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| {
                let length = unsafe {
                    libc::write(
                        fd.get_ref().as_raw_fd(),
                        packet[offset..].as_ptr().cast(),
                        packet.len() - offset,
                    )
                };
                if length < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(length as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "TUN write returned zero").into(),
                    )
                }
                Ok(Ok(length)) => offset += length,
                Ok(Err(error)) => return Err(error.into()),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        remove_route_policy(self.local, &self.name, &self.route_policy);
        let status = Command::new("ip")
            .args(["link", "delete", "dev", &self.name])
            .status();
        if !status.is_ok_and(|status| status.success()) {
            warn!(interface = %self.name, "failed to remove TUN interface");
        }
    }
}

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

impl Default for IfReq {
    fn default() -> Self {
        Self {
            name: [0; libc::IFNAMSIZ],
            flags: 0,
            padding: [0; 22],
        }
    }
}

fn run_ip(arguments: &[&str]) -> Result<()> {
    let status = Command::new("ip").args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::NetworkConfiguration(format!(
            "ip {} exited with {status}",
            arguments.join(" ")
        )))
    }
}

fn tunnel_address_arguments(local: Ipv4Addr, name: &str) -> Vec<String> {
    vec![
        "addr".into(),
        "replace".into(),
        format!("{local}/32"),
        "dev".into(),
        name.into(),
    ]
}

struct RoutePolicyArguments {
    route: Vec<String>,
    rule: Vec<String>,
    delete_rule: Vec<String>,
    delete_route: Vec<String>,
}

struct RoutePolicy {
    table: u32,
}

fn route_policy_arguments(local: Ipv4Addr, name: &str, table: u32) -> RoutePolicyArguments {
    let source = format!("{local}/32");
    let table = table.to_string();
    RoutePolicyArguments {
        route: vec![
            "route".into(),
            "add".into(),
            "table".into(),
            table.clone(),
            "default".into(),
            "dev".into(),
            name.into(),
        ],
        rule: vec![
            "rule".into(),
            "add".into(),
            "from".into(),
            source.clone(),
            "lookup".into(),
            table.clone(),
        ],
        delete_rule: vec![
            "rule".into(),
            "del".into(),
            "from".into(),
            source,
            "lookup".into(),
            table.clone(),
        ],
        delete_route: vec![
            "route".into(),
            "del".into(),
            "table".into(),
            table,
            "default".into(),
            "dev".into(),
            name.into(),
        ],
    }
}

fn configure_route_policy(local: Ipv4Addr, name: &str) -> Result<RoutePolicy> {
    let mut used = current_route_tables()?;
    loop {
        let table = select_route_table(&used).ok_or_else(|| {
            Error::NetworkConfiguration("no unused route policy table is available".into())
        })?;
        let arguments = route_policy_arguments(local, name, table);
        if let Err(error) = run_ip(&as_strs(&arguments.route)) {
            let refreshed = current_route_tables()?;
            if refreshed.contains(&table) {
                used = refreshed;
                continue;
            }
            return Err(error);
        }
        if let Err(error) = run_ip(&as_strs(&arguments.rule)) {
            run_ip_best_effort(&arguments.delete_route);
            return Err(error);
        }
        return Ok(RoutePolicy { table });
    }
}

fn remove_route_policy(local: Ipv4Addr, name: &str, policy: &RoutePolicy) {
    let arguments = route_policy_arguments(local, name, policy.table);
    run_ip_best_effort(&arguments.delete_rule);
    run_ip_best_effort(&arguments.delete_route);
}

fn run_ip_best_effort(arguments: &[String]) {
    let status = Command::new("ip")
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !status.is_ok_and(|status| status.success()) {
        warn!(command = %format!("ip {}", arguments.join(" ")), "failed to clean up route policy");
    }
}

fn as_strs(arguments: &[String]) -> Vec<&str> {
    arguments.iter().map(String::as_str).collect()
}

fn current_route_tables() -> Result<BTreeSet<u32>> {
    let routes = run_ip_capture(&["-N", "route", "show", "table", "all"])?;
    let rules = run_ip_capture(&["-N", "rule", "show"])?;
    Ok(configured_route_tables(&routes, &rules))
}

fn run_ip_capture(arguments: &[&str]) -> Result<String> {
    let output = Command::new("ip").args(arguments).output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::NetworkConfiguration(format!(
            "ip {} exited with {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn configured_route_tables(routes: &str, rules: &str) -> BTreeSet<u32> {
    routes
        .lines()
        .chain(rules.lines())
        .flat_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields
                .windows(2)
                .filter(|pair| pair[0] == "table" || pair[0] == "lookup")
                .filter_map(|pair| pair[1].parse().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn select_route_table(used: &BTreeSet<u32>) -> Option<u32> {
    (ROUTE_TABLE_START..ROUTE_TABLE_END).find(|table| !used.contains(table))
}

#[cfg(test)]
mod tests {
    use super::{
        configured_route_tables, route_policy_arguments, select_route_table,
        tunnel_address_arguments,
    };

    #[test]
    fn tunnel_address_does_not_install_a_peer_route() {
        assert_eq!(
            tunnel_address_arguments("121.126.139.11".parse().unwrap(), "haiip0"),
            ["addr", "replace", "121.126.139.11/32", "dev", "haiip0"]
        );
    }

    #[test]
    fn route_policy_sends_only_tunnel_sourced_traffic_through_tun() {
        let arguments = route_policy_arguments("121.126.139.11".parse().unwrap(), "haiip0", 20_001);

        assert_eq!(
            arguments.route,
            ["route", "add", "table", "20001", "default", "dev", "haiip0",]
        );
        assert_eq!(
            arguments.rule,
            [
                "rule",
                "add",
                "from",
                "121.126.139.11/32",
                "lookup",
                "20001",
            ]
        );
    }

    #[test]
    fn route_table_selection_skips_tables_used_by_routes_or_rules() {
        let used = configured_route_tables(
            "default dev other0 table 20000 scope link\n",
            "32765: from 203.0.113.1 lookup 20001\n",
        );

        assert_eq!(select_route_table(&used), Some(20_002));
    }

    #[test]
    fn separate_instances_get_separate_route_tables() {
        let mut used = configured_route_tables("", "");
        let first = select_route_table(&used).unwrap();
        used.insert(first);

        assert_ne!(select_route_table(&used), Some(first));
    }
}
