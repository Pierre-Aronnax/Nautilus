// protocols/mdns/src/behaviour/service/socket.rs

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use crate::MdnsError;

/// ===========================
/// Sets up the multicast UDP socket for mDNS communication.
/// - Creates a UDP socket using the `socket2` crate.
/// - Sets reuse options and binds to the appropriate address/port.
/// - Joins the mDNS multicast group at `224.0.0.251:5353`.
/// ===========================
pub async fn setup_multicast_socket() -> Result<UdpSocket, MdnsError> {
    let multicast_addr = Ipv4Addr::new(224, 0, 0, 251);
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let port = 5353;

    // Create a new IPv4 UDP socket.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(MdnsError::NetworkError)?;

    // Allow multiple sockets to bind to the same address.
    socket
        .set_reuse_address(true)
        .map_err(MdnsError::NetworkError)?;
    
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(MdnsError::NetworkError)?;

    // Bind to the local address and port.
    socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(local_addr, port)).into())
        .map_err(MdnsError::NetworkError)?;

    // Convert the `socket2` socket into a `Tokio` UdpSocket.
    let udp_socket = UdpSocket::from_std(socket.into()).map_err(MdnsError::NetworkError)?;

    // Join the multicast group.
    udp_socket
        .join_multicast_v4(multicast_addr, local_addr)
        .map_err(MdnsError::NetworkError)?;

    println!("(INIT) Multicast socket set up on {}:{}", multicast_addr, port);
    Ok(udp_socket)
}

/// ===========================
/// Helper: Retrieves the local IPv4 address (e.g., `192.168.x.x`).
/// ===========================
pub fn get_local_ipv4() -> Option<Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};

    // Bind a UDP socket to an ephemeral port and connect to an external address.
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    
    if let Ok(local_addr) = socket.local_addr() {
        if let IpAddr::V4(ip) = local_addr.ip() {
            return Some(ip);
        }
    }
    None
}
