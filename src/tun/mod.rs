use std::{
    fs::OpenOptions,
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
};

use tokio::io::unix::AsyncFd;

use crate::error::{Error, Result};

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    pub name: String,
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
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            name: name.to_owned(),
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
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", &self.name])
            .status();
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

#[cfg(test)]
mod tests {
    use super::tunnel_address_arguments;

    #[test]
    fn tunnel_address_does_not_install_a_peer_route() {
        assert_eq!(
            tunnel_address_arguments("121.126.139.11".parse().unwrap(), "haiip0"),
            ["addr", "replace", "121.126.139.11/32", "dev", "haiip0"]
        );
    }
}
