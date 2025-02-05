use crate::behaviour::records::{NodeRecord, ServiceRecord};
use crate::{DnsName, DnsPacket, DnsRecord, MdnsError, MdnsRegistry, MdnsEvent};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{self, Duration};

/// Represents the mDNS service, including registry management and network communication.
pub struct MdnsService {
    socket: Arc<UdpSocket>,
    pub registry: Arc<MdnsRegistry>,
    event_sender: broadcast::Sender<MdnsEvent>,
    origin: Arc<RwLock<Option<String>>>,
    pub default_service_type: String,  // <--- [NEW] store the default service type
}

impl MdnsService {
    /// Sets up a multicast UDP socket for mDNS communication.
    async fn setup_multicast_socket() -> Result<UdpSocket, MdnsError> {
        let multicast_addr = Ipv4Addr::new(224, 0, 0, 251);
        let local_addr = Ipv4Addr::UNSPECIFIED;
        let port = 5353;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(MdnsError::NetworkError)?;
        socket
            .set_reuse_address(true)
            .map_err(MdnsError::NetworkError)?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(MdnsError::NetworkError)?;

        socket
            .bind(&SocketAddr::V4(SocketAddrV4::new(local_addr, port)).into())
            .map_err(MdnsError::NetworkError)?;

        let udp_socket = UdpSocket::from_std(socket.into()).map_err(MdnsError::NetworkError)?;
        udp_socket
            .join_multicast_v4(multicast_addr, local_addr)
            .map_err(MdnsError::NetworkError)?;

        println!("(INIT) Multicast socket set up on {}:{}", multicast_addr, port);
        Ok(udp_socket)
    }

    /// Creates a new mDNS service instance. We also register a default node service so that
    /// the node is always discoverable by at least one service type.
    pub async fn new(
        origin: Option<String>,
        default_service_type: &str, // user picks what the "compulsory" service type is
    ) -> Result<Arc<Self>, MdnsError> {
        let socket = Self::setup_multicast_socket().await?;
        let registry = MdnsRegistry::new();
        let (event_sender, _) = broadcast::channel(100);

        let service = Arc::new(Self {
            socket: Arc::new(socket),
            registry,
            event_sender,
            origin: Arc::new(RwLock::new(origin)),
            default_service_type: default_service_type.to_string(),
        });

        // [NEW] Register the default service for our local node:
        service.register_default_node_service().await?;

        Ok(service)
    }

    /// Registers the *compulsory* "default" service for this node.
    pub async fn register_default_node_service(&self) -> Result<(), MdnsError> {
        let node_origin = {
            let origin_lock = self.origin.read().await;
            origin_lock
                .clone()
                .unwrap_or_else(|| "UnknownOrigin.local".to_string())
        };

        // e.g. "MyLaptop.local._mdnsnode._tcp.local."
        let default_id = format!(
            "{}.{}",
            node_origin.trim_end_matches('.'),
            self.default_service_type.trim_start_matches('.')
        );

        // Construct the never-expiring default service
        let service_record = ServiceRecord {
            id: default_id.clone(),
            service_type: self.default_service_type.clone(),
            port: 5353,             // or a relevant port
            ttl: Some(u32::MAX),    // never expires
            origin: node_origin.clone(),
            priority: Some(0),
            weight: Some(0),
            node_id: node_origin.clone(),
        };

        // Add the service to the registry
        self.registry.add_service(service_record.clone()).await?;

        // Also ensure the node record exists and references this service
        self.link_service_to_node(&service_record).await?;

        println!("(DEFAULT-SERVICE) Registered default node service: {}", default_id);
        Ok(())
    }

    /// Public helper to retrieve a broadcast receiver for events.
    pub fn get_event_receiver(&self) -> broadcast::Receiver<MdnsEvent> {
        self.event_sender.subscribe()
    }

    /// Registers a local ephemeral (non-default) service to the registry.
    ///
    /// **Also** updates the node so that `NodeRecord.services` contains this service ID.
    pub async fn register_local_service(
        &self,
        id: String,
        service_type: String,
        port: u16,
        ttl: Option<u32>,
        origin: String,
    ) -> Result<(), MdnsError> {
        let service = ServiceRecord {
            id: id.clone(),
            service_type,
            port,
            ttl,
            origin: origin.clone(),
            priority: Some(0),
            weight: Some(0),
            node_id: origin.clone(),
        };

        self.registry.add_service(service.clone()).await?;

        // Link the service to the node
        self.link_service_to_node(&service).await?;

        // Optionally, broadcast an event
        let _ = self.event_sender.send(MdnsEvent::Discovered(DnsRecord::SRV {
            name: DnsName::new(&service.id).unwrap(),
            ttl: service.ttl.unwrap_or(120),
            priority: service.priority.unwrap_or(0),
            weight: service.weight.unwrap_or(0),
            port: service.port,
            target: DnsName::new(&service.origin).unwrap(),
        }));

        Ok(())
    }

    /// [NEW] Updates the NodeRecord in the registry so that it includes the given service's ID.
    /// If the node doesn't exist, we create it; if it does, we add the service ID to the list.
    async fn link_service_to_node(&self, service: &ServiceRecord) -> Result<(), MdnsError> {
        // Find or create the NodeRecord
        let node_id = service.node_id.trim_end_matches('.').to_string();

        let mut node_opt = self.registry.get_node(&node_id).await;
        if node_opt.is_none() {
            // Node doesn't exist yet, create it
            node_opt = Some(NodeRecord {
                id: node_id.clone(),
                ip_address: "0.0.0.0".to_string(),
                ttl: service.ttl,
                services: Vec::new(),
            });
        }

        if let Some(mut node) = node_opt {
            // Add this service ID if it's not already in the node's list
            if !node.services.contains(&service.id) {
                node.services.push(service.id.clone());
            }
            // Update the node record in the registry
            self.registry.add_node(node).await?;
        }

        Ok(())
    }

    /// Creates an mDNS "advertise" packet with all services registered under this node.
    pub async fn create_advertise_packet(&self) -> Result<DnsPacket, MdnsError> {
        let origin = {
            let origin_lock = self.origin.read().await;
            origin_lock.clone().unwrap_or_else(|| "UnknownOrigin.local".to_string())
        };

        let services = self.registry.list_services_by_node(&origin).await;
        let mut packet = DnsPacket::new();
        packet.flags = 0x8400; // Set response flags

        let local_ip = get_local_ipv4()
            .ok_or_else(|| MdnsError::Generic("Failed to get local IP".to_string()))?;

        if services.is_empty() {
            println!("(ADVERTISE) No local services to advertise.");
        } else {
            for service in services {
                println!("(ADVERTISE) Including service in packet: {:?}", service);

                packet.answers.push(DnsRecord::PTR {
                    name: DnsName::new(&service.service_type).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ptr_name: DnsName::new(&service.id).unwrap(),
                });

                packet.answers.push(DnsRecord::SRV {
                    name: DnsName::new(&service.id).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    priority: service.priority.unwrap_or(0),
                    weight: service.weight.unwrap_or(0),
                    port: service.port,
                    target: DnsName::new(&origin).unwrap(),
                });

                packet.answers.push(DnsRecord::A {
                    name: DnsName::new(&service.origin).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ip: local_ip.octets(),
                });
            }
        }

        Ok(packet)
    }

    /// Sends an mDNS packet over the network to the multicast address.
    pub async fn send_packet(&self, packet: &DnsPacket) -> Result<(), MdnsError> {
        let bytes = packet.serialize();
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));

        self.socket
            .send_to(&bytes, multicast_addr)
            .await
            .map_err(MdnsError::NetworkError)?;

        Ok(())
    }

    /// Periodically sends a PTR query for the given service type.
    pub async fn periodic_query(&self, service_type: &str, interval_secs: u64) {
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let mut packet = DnsPacket::new();
            packet.flags = 0x0000;
            packet.questions.push(crate::DnsQuestion {
                qname: DnsName::new(service_type).unwrap(),
                qtype: 12, // PTR
                qclass: 1,
            });

            if let Err(err) = self.send_packet(&packet).await {
                eprintln!("(QUERY) Failed to send periodic query: {:?}", err);
            } else {
                println!("(QUERY) Periodic query sent for service type: {}", service_type);
            }
        }
    }

    /// Advertises all local services (including the default service) as unsolicited mDNS responses.
    pub async fn advertise_services(&self) -> Result<(), MdnsError> {
        let packet = self.create_advertise_packet().await?;
        if packet.answers.is_empty() {
            println!("(ADVERTISE) No answers in the mDNS packet.");
        } else {
            println!(
                "(ADVERTISE) Sending mDNS packet with {} answers.",
                packet.answers.len()
            );
        }
        self.send_packet(&packet).await
    }

    /// Core loop listening for incoming mDNS packets and processing them.
    pub async fn listen(&self) -> Result<(), MdnsError> {
        let mut buf = [0; 4096];
        loop {
            let (len, src) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(MdnsError::NetworkError)?;

            if let Ok(packet) = DnsPacket::parse(&buf[..len]) {
                let is_response = (packet.flags & 0x8000) != 0;
                if is_response {
                    self.process_response(&packet, &src).await;
                } else {
                    self.process_query(&packet, &src).await;
                }
            } else {
                eprintln!("(LISTEN) Failed to parse packet from {}", src);
            }
        }
    }

    /// Periodically logs all nodes in the registry (debugging).
    pub async fn print_node_registry(&self) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let nodes = self.registry.list_nodes().await;
            println!("(NODE REGISTRY) Nodes: {:?}", nodes);
        }
    }

    /// Spawns tasks: (1) periodically advertise, (2) periodically query, (3) listen, (4) debug-print.
    pub async fn run(
        self: &Arc<Self>,
        query_service_type: String,
        query_interval: u64,
        advertise_interval: u64,
    ) {
        let advertise_service = Arc::clone(self);
        let query_service = Arc::clone(self);
        let listen_service = Arc::clone(self);
        let registry_service = Arc::clone(self);

        // Periodic advertisement
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(advertise_interval)).await;
                if let Err(err) = advertise_service.advertise_services().await {
                    eprintln!("(ADVERTISE) Error: {:?}", err);
                }
            }
        });

        // Periodic query for a specific service type (e.g. "_myservice._http._tcp.local.")
        tokio::spawn(async move {
            query_service
                .periodic_query(&query_service_type, query_interval)
                .await;
        });

        // Listen loop
        tokio::spawn(async move {
            if let Err(err) = listen_service.listen().await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        // Print registry
        tokio::spawn(async move {
            registry_service.print_node_registry().await;
        });
    }

    /// Process a response packet: see if it has A/SRV records, update registry accordingly.
    pub async fn process_response(&self, packet: &DnsPacket, src: &SocketAddr) {
        println!("Packet : {:?}", packet);

        // If it's IPv4
        if let SocketAddr::V4(src_addr) = src {
            for answer in &packet.answers {
                match answer {
                    // If there's an A record => we discover a node's IP
                    DnsRecord::A { name, ip, ttl } => {
                        let ip_address = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        println!(
                            "(DISCOVERY) Discovered node: {} -> {} <=> {}",
                            name,
                            ip_address,
                            src_addr.ip()
                        );

                        // Add/Update node
                        if let Err(e) =
                            self.add_node_to_registry(&name.to_string(), &src_addr.ip().to_string(), Some(*ttl)).await
                        {
                            eprintln!("(DISCOVERY) Failed to add node: {:?}", e);
                        }

                        // Send an event
                        let _ = self.event_sender.send(MdnsEvent::Discovered(answer.clone()));
                    }

                    // [NEW] If there's an SRV record => we discover a node's service
                    DnsRecord::SRV {
                        name,
                        ttl,
                        port,
                        priority,
                        weight,
                        target,
                    } => {
                        println!(
                            "(DISCOVERY) Discovered service: {} => node: {}, port: {}",
                            name, target, port
                        );
                        // Example: name = "MyLaptop.local._myDefault._tcp.local."
                        // target = "MyLaptop.local."

                        // We'll create a ServiceRecord that matches this SRV
                        let srv_id = name.to_string();
                        let srv_origin = target.to_string().trim_end_matches('.').to_string();

                        let service_record = ServiceRecord {
                            id: srv_id.clone(),
                            service_type: extract_service_type(&srv_id), // see helper below
                            port: *port,
                            ttl: Some(*ttl),
                            origin: srv_origin.clone(),
                            priority: Some(*priority),
                            weight: Some(*weight),
                            node_id: srv_origin.clone(),
                        };

                        // Add that to our registry
                        if let Err(e) = self.registry.add_service(service_record.clone()).await {
                            eprintln!("(DISCOVERY) Failed to add service: {:?}", e);
                        } else {
                            // Link it to the node
                            if let Err(e) = self.link_service_to_node(&service_record).await {
                                eprintln!("(DISCOVERY) Failed to link service to node: {:?}", e);
                            }
                        }

                        // Optional event
                        let _ = self.event_sender.send(MdnsEvent::Discovered(answer.clone()));
                    }

                    // Others (e.g. PTR, AAAA, etc.)
                    _ => {}
                }
            }
        }

        // After we process everything, print the updated registry
        let updated_nodes = self.registry.list_nodes().await;
        println!("(REGISTRY) Current nodes: {:?}", updated_nodes);
    }

    /// Process a query packet: see if we have a matching service type, respond accordingly.
    async fn process_query(&self, packet: &DnsPacket, src: &SocketAddr) {
        for question in &packet.questions {
            if question.qtype == 12 && question.qclass == 1 {
                let requested_service = question.qname.labels.join(".");
                let all_services = self.registry.list_services().await;

                println!("Requested Service : {}", requested_service);

                // Find all services whose `id` ends with the requested service
                let matching_services: Vec<_> = all_services
                    .into_iter()
                    .filter(|s| {
                        s.id.trim_end_matches('.')
                            .ends_with(&requested_service.trim_end_matches('.'))
                    })
                    .collect();

                if matching_services.is_empty() {
                    println!("(QUERY) No matching service for '{}'", requested_service);
                    continue;
                }

                let mut response_packet = DnsPacket::new();
                response_packet.flags = 0x8400;

                let origin = {
                    let origin_lock = self.origin.read().await;
                    origin_lock
                        .clone()
                        .unwrap_or_else(|| "UnknownOrigin.local".to_string())
                };

                // Build answers
                for service in matching_services {
                    response_packet.answers.push(DnsRecord::PTR {
                        name: DnsName::new(&service.service_type).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        ptr_name: DnsName::new(&service.id).unwrap(),
                    });

                    response_packet.answers.push(DnsRecord::SRV {
                        name: DnsName::new(&service.id).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        priority: service.priority.unwrap_or(0),
                        weight: service.weight.unwrap_or(0),
                        port: service.port,
                        target: DnsName::new(&origin).unwrap(),
                    });

                    if let SocketAddr::V4(addr) = src {
                        response_packet.answers.push(DnsRecord::A {
                            name: DnsName::new(&origin).unwrap(),
                            ttl: service.ttl.unwrap_or(120),
                            ip: addr.ip().octets(),
                        });
                    }
                }

                // Send the response
                if let Err(err) = self.send_packet(&response_packet).await {
                    eprintln!("(QUERY->RESP) Failed to send response: {:?}", err);
                }
            }
        }
    }

    /// Adds or updates a NodeRecord in the registry. (Mostly used for discovered A records.)
    async fn add_node_to_registry(
        &self,
        id: &str,
        ip_address: &str,
        ttl: Option<u32>,
    ) -> Result<(), MdnsError> {
        let normalized_id = id.trim_end_matches('.').to_string();
        let ip_address = ip_address.to_string();

        let mut nodes = self.registry.list_nodes().await;

        // If there's a conflict
        if let Some(conflict) = nodes.iter().find(|n| n.ip_address == ip_address && n.id != normalized_id) {
            return Err(MdnsError::Generic(format!(
                "IP conflict: {} is already assigned to {}",
                ip_address, conflict.id
            )));
        }

        // If it already exists, update IP if needed:
        if let Some(existing_node) = nodes.iter_mut().find(|n| n.id == normalized_id) {
            if existing_node.ip_address != ip_address {
                existing_node.ip_address = ip_address.clone();
                existing_node.ttl = ttl;
                // re-save
                self.registry
                    .add_node(existing_node.clone())
                    .await
                    .map_err(|e| MdnsError::Generic(e.to_string()))?;
            }
        } else {
            // Create new node
            println!("(DISCOVERY) Adding new node: {} with IP {}", normalized_id, ip_address);

            let new_node = NodeRecord {
                id: normalized_id.clone(),
                ip_address,
                ttl,
                services: Vec::new(),
            };
            self.registry
                .add_node(new_node)
                .await
                .map_err(|e| MdnsError::Generic(e.to_string()))?;
        }

        Ok(())
    }
}

/// Helper to get the local IPv4 address, e.g. 192.168.x.x
fn get_local_ipv4() -> Option<Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    if let Ok(local_addr) = socket.local_addr() {
        if let IpAddr::V4(ip) = local_addr.ip() {
            return Some(ip);
        }
    }
    None
}

/// [NEW] Example function to derive "service type" from an SRV record's name, e.g.
/// If `srv_id = "MyLaptop.local._myDefault._tcp.local."`,
/// we parse out `_myDefault._tcp.local.` as the service type.
fn extract_service_type(srv_id: &str) -> String {
    // A simple approach: find the first dot from the left after the node portion.
    // But many ways to do it. This is just an example logic.
    if let Some(pos) = srv_id.find("._") {
        // return everything from that '.' onward
        // e.g. "._myDefault._tcp.local."
        return srv_id[pos+1..].to_string(); 
    }
    // fallback
    srv_id.to_string()
}
