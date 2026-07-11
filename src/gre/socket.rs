use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use tokio::io::unix::AsyncFd;

use crate::error::{Error, Result};

pub struct GreSocket {
    fd: AsyncFd<OwnedFd>,
    peer: libc::sockaddr_in,
}

impl GreSocket {
    pub fn open(peer: Ipv4Addr) -> Result<Self> {
        let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_GRE) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let peer = sockaddr(peer);
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            peer,
        })
    }

    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let result = guard.try_io(|fd| {
                let written = unsafe {
                    libc::sendto(
                        fd.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&self.peer as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                if written < 0 {
                    Err(io::Error::last_os_error())
                } else if written as usize != packet.len() {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial raw GRE datagram",
                    ))
                } else {
                    Ok(())
                }
            });
            match result {
                Ok(value) => return value.map_err(Error::from),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn receive(&self, buffer: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
        loop {
            let mut guard = self.fd.readable().await?;
            let result = guard.try_io(|fd| {
                let mut source: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                let mut source_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                let received = unsafe {
                    libc::recvfrom(
                        fd.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        0,
                        (&mut source as *mut libc::sockaddr_in).cast(),
                        &mut source_len,
                    )
                };
                if received < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok((
                        received as usize,
                        Ipv4Addr::from(u32::from_be(source.sin_addr.s_addr)),
                    ))
                }
            });
            match result {
                Ok(value) => return value.map_err(Error::from),
                Err(_would_block) => continue,
            }
        }
    }
}

fn sockaddr(address: Ipv4Addr) -> libc::sockaddr_in {
    let socket = SocketAddrV4::new(address, 0);
    let mut output: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    output.sin_family = libc::AF_INET as libc::sa_family_t;
    output.sin_addr.s_addr = u32::from_ne_bytes(socket.ip().octets());
    output
}
