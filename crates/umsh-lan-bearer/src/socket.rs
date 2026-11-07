//! Group membership.
//!
//! One socket, bound to the group's port, which every participant both
//! sends from and listens on; several participants on one host share it.
//! A multicast group is joined, and a participant hears its own datagrams
//! when multicast loopback hands them back, which the node above already
//! tolerates. A unicast address in place of the group names the one peer
//! of a point-to-point link: nothing is joined, and only datagrams from
//! that peer's address and port are taken.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::{DEFAULT_GROUP, DEFAULT_PORT, MAX_FRAME, MULTICAST_TTL};

/// Where and how to join the group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanConfig {
    /// The group address and port.
    pub group: SocketAddrV4,
    /// The interface to join on, by its address. Unspecified picks the
    /// interface the host routes the group through.
    pub interface: Ipv4Addr,
    /// Whether this host's other participants hear what this one sends.
    /// Off for a host with one participant, such as a radio; on for a
    /// desktop that may run several.
    pub loopback: bool,
}

impl LanConfig {
    /// The default group on the routed interface, with loopback on.
    pub fn lan() -> Self {
        Self {
            group: SocketAddrV4::new(Ipv4Addr::from(DEFAULT_GROUP), DEFAULT_PORT),
            interface: Ipv4Addr::UNSPECIFIED,
            loopback: true,
        }
    }

    /// A group confined to this host: joined on the loopback interface,
    /// where only this host's own participants hear it. What the desktop
    /// simulations and the tests use.
    pub fn host_local(group: Ipv4Addr, port: u16) -> Self {
        Self {
            group: SocketAddrV4::new(group, port),
            interface: Ipv4Addr::LOCALHOST,
            loopback: true,
        }
    }
}

/// A participant's membership in the group.
pub struct LanSocket {
    socket: UdpSocket,
    group: SocketAddrV4,
}

impl LanSocket {
    /// Join the group described by `config`, or, for a unicast address,
    /// listen for that one peer.
    pub fn bind(config: LanConfig) -> io::Result<Self> {
        let group = *config.group.ip();
        if group.is_unspecified() || group.is_broadcast() || config.group.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the group must be a multicast group or a peer, with a nonzero port",
            ));
        }
        let interface = match config.interface {
            Ipv4Addr::UNSPECIFIED => routed_interface(config.group)?,
            interface => interface,
        };

        // The group's port, shared with every participant on the host,
        // for sending as well as receiving: a peer knows where to answer.
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.group.port()).into())?;
        if group.is_multicast() {
            socket.set_multicast_if_v4(&interface)?;
            socket.set_multicast_ttl_v4(MULTICAST_TTL)?;
            socket.set_multicast_loop_v4(config.loopback)?;
            socket.join_multicast_v4(&group, &interface)?;
        }
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(StdUdpSocket::from(socket))?;

        Ok(Self {
            socket,
            group: config.group,
        })
    }

    /// The group this participant joined.
    pub fn group(&self) -> SocketAddrV4 {
        self.group
    }

    /// Send one frame to the group.
    pub async fn send(&self, frame: &[u8]) -> io::Result<()> {
        if frame.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a frame larger than 255 octets cannot be sent",
            ));
        }
        self.socket.send_to(frame, self.group).await?;
        Ok(())
    }

    /// Poll for the next datagram, copying it into `buf` and returning its
    /// length and source. On a point-to-point link, datagrams from anyone
    /// but the peer are dropped here.
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        loop {
            let mut read = ReadBuf::new(buf);
            let source = match self.socket.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(source)) => source,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            if !self.group.ip().is_multicast() && source != SocketAddr::V4(self.group) {
                continue;
            }
            return Poll::Ready(Ok((read.filled().len(), source)));
        }
    }

    /// Receive the next datagram.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }
}

/// The address of the interface the host would send to `group` through.
///
/// Connecting a UDP socket sends nothing; it only asks the routing table.
/// The answer changes when the network does—a new DHCP lease, a roam to
/// another network—and a membership joined on the old address no longer
/// hears the group, so a long-lived participant asks again from time to
/// time.
pub fn routed_interface(group: SocketAddrV4) -> io::Result<Ipv4Addr> {
    let probe = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    probe.connect(group)?;
    match probe.local_addr()? {
        SocketAddr::V4(local) if !local.ip().is_unspecified() => Ok(*local.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 interface routes to the group",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 101);

    async fn recv_within(socket: &LanSocket, ms: u64) -> Option<Vec<u8>> {
        let mut buf = [0u8; 512];
        tokio::time::timeout(Duration::from_millis(ms), socket.recv(&mut buf))
            .await
            .ok()
            .map(|result| buf[..result.unwrap().0].to_vec())
    }

    /// Several participants on one host each hear every frame sent to the
    /// group, their own included, however many frames are in flight.
    #[tokio::test]
    async fn every_participant_hears_the_group() {
        let config = LanConfig::host_local(GROUP, 47_101);
        let a = LanSocket::bind(config).unwrap();
        let b = LanSocket::bind(config).unwrap();
        let c = LanSocket::bind(config).unwrap();

        for tag in 0..3u8 {
            a.send(&[0xC0, tag]).await.unwrap();
        }
        b.send(&[0xC0, 0xBB]).await.unwrap();

        for socket in [&a, &b, &c] {
            let mut heard = Vec::new();
            while let Some(frame) = recv_within(socket, 200).await {
                heard.push(frame);
            }
            assert_eq!(heard.len(), 4);
        }
    }

    /// A unicast address stands in for the group: datagrams come and go on
    /// the shared port, and only the peer's are taken.
    #[tokio::test]
    async fn a_unicast_peer_is_the_only_one_heard() {
        // The peer is this host's own address on the shared port, so the
        // socket is its own peer.
        let port = 47_104;
        let socket = LanSocket::bind(LanConfig::host_local(Ipv4Addr::LOCALHOST, port)).unwrap();
        let stranger = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        stranger
            .send_to(&[0xC0, 0x55], (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        socket.send(&[0xC0, 0xAA]).await.unwrap();
        assert_eq!(recv_within(&socket, 200).await, Some(vec![0xC0, 0xAA]));
        assert_eq!(recv_within(&socket, 200).await, None);
    }

    #[tokio::test]
    async fn only_a_usable_group_and_a_fitting_frame() {
        assert!(LanSocket::bind(LanConfig::host_local(Ipv4Addr::UNSPECIFIED, 47_102)).is_err());
        assert!(LanSocket::bind(LanConfig::host_local(Ipv4Addr::BROADCAST, 47_102)).is_err());
        let socket = LanSocket::bind(LanConfig::host_local(GROUP, 47_103)).unwrap();
        assert!(socket.send(&[0xC0; MAX_FRAME + 1]).await.is_err());
    }
}
