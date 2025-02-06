// protocols\mdns\src\behaviour\mdns_service.rs
use crate::behaviour::records::{NodeRecord, ServiceRecord};
use crate::{
    DnsName, DnsPacket, DnsRecord, MdnsError, MdnsEvent, MdnsRegistry,
    behaviour::back_off::BackoffState,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{self, Duration};
use std::sync::atomic::{AtomicU64, Ordering};

/// ===========================
/// MdnsService: Represents the mDNS service,
/// handling registry management and network communication.
/// ===========================
pub struct MdnsService {
    socket: Arc<UdpSocket>,
    pub registry: Arc<MdnsRegistry>,
    event_sender: broadcast::Sender<MdnsEvent>,
    origin: Arc<RwLock<Option<String>>>,
    pub default_service_type: String,
    pub query_cache: Arc<Mutex<HashMap<String, u64>>>,
    pub backoff_state: Arc<Mutex<BackoffState>>,
    pub backoff_interval_advertise: AtomicU64,
    pub backoff_interval_query: AtomicU64,
}

impl MdnsService {
    // ===========================
    // Setup the multicast UDP socket for mDNS communication.
    // - Creates a UDP socket using the socket2 crate.
    // - Sets reuse options and binds to the appropriate address/port.
    // - Joins the mDNS multicast group at 224.0.0.251:5353.
    // ===========================
    async fn setup_multicast_socket() -> Result<UdpSocket, MdnsError> {
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

        // Convert the socket2 socket into a Tokio UdpSocket.
        let udp_socket = UdpSocket::from_std(socket.into()).map_err(MdnsError::NetworkError)?;
        // Join the multicast group.
        udp_socket
            .join_multicast_v4(multicast_addr, local_addr)
            .map_err(MdnsError::NetworkError)?;

        println!(
            "(INIT) Multicast socket set up on {}:{}",
            multicast_addr, port
        );
        Ok(udp_socket)
    }

    // ===========================
    // Create a new instance of MdnsService.
    // - Sets up the multicast socket.
    // - Initializes the registry, event channel, and default parameters.
    // - Registers the compulsory default node service.
    // ===========================
    pub async fn new(
        origin: Option<String>,
        default_service_type: &str,
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
            query_cache: Arc::new(Mutex::new(HashMap::new())),
            backoff_state: Arc::new(Mutex::new(BackoffState::Normal)),
            backoff_interval_advertise: AtomicU64::new(5),
            backoff_interval_query: AtomicU64::new(5),
        });
        service.register_default_node_service().await?;

        Ok(service)
    }

    // ===========================
    // Registers the compulsory "default" service for this node.
    // - Retrieves the origin.
    // - Constructs a default service record.
    // - Adds it to the registry and links it to the node.
    // ===========================
    pub async fn register_default_node_service(&self) -> Result<(), MdnsError> {
        let node_origin = {
            let origin_lock = self.origin.read().await;
            origin_lock
                .clone()
                .unwrap_or_else(|| "UnknownOrigin.local".to_string())
        };

        let default_id = format!(
            "{}.{}",
            node_origin.trim_end_matches('.'),
            self.default_service_type.trim_start_matches('.')
        );

        let service_record = ServiceRecord {
            id: default_id.clone(),
            service_type: self.default_service_type.clone(),
            port: 5353,         // Use standard mDNS port.
            ttl: Some(u32::MAX), // A high TTL to indicate a long-lived record.
            origin: node_origin.clone(),
            priority: Some(0),
            weight: Some(0),
            node_id: node_origin.clone(),
        };

        self.registry.add_service(service_record.clone()).await?;
        self.link_service_to_node(&service_record).await?;

        println!(
            "(DEFAULT-SERVICE) Registered default node service: {}",
            default_id
        );
        Ok(())
    }

    // ===========================
    // Returns a new event receiver subscribing to mDNS events.
    // ===========================
    pub fn get_event_receiver(&self) -> broadcast::Receiver<MdnsEvent> {
        self.event_sender.subscribe()
    }

    // ===========================
    // Registers a local service.
    // - Constructs a service record from the provided parameters.
    // - Adds the record to the registry and links it to the node.
    // - Notifies listeners via the event channel.
    // ===========================
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
        self.link_service_to_node(&service).await?;

        let _ = self
            .event_sender
            .send(MdnsEvent::Discovered(DnsRecord::SRV {
                name: DnsName::new(&service.id).unwrap(),
                ttl: service.ttl.unwrap_or(120),
                priority: service.priority.unwrap_or(0),
                weight: service.weight.unwrap_or(0),
                port: service.port,
                target: DnsName::new(&service.origin).unwrap(),
            }));

        Ok(())
    }

    // ===========================
    // Links a given service record to its corresponding node record.
    // - If the node does not exist, a new one is created with a default IP.
    // - Otherwise, the service is added to the node's list if not already present.
    // ===========================
    async fn link_service_to_node(&self, service: &ServiceRecord) -> Result<(), MdnsError> {
        let node_id = service.node_id.trim_end_matches('.').to_string();

        let mut node_opt = self.registry.get_node(&node_id).await;
        if node_opt.is_none() {
            node_opt = Some(NodeRecord {
                id: node_id.clone(),
                ip_address: "0.0.0.0".to_string(),
                ttl: service.ttl,
                services: Vec::new(),
            });
        }

        if let Some(mut node) = node_opt {
            if !node.services.contains(&service.id) {
                node.services.push(service.id.clone());
            }
            self.registry.add_node(node).await?;
        }

        Ok(())
    }

    // ===========================
    // Creates an mDNS advertisement packet containing PTR, SRV, and A records.
    // - Retrieves local services from the registry.
    // - Determines the local IP address using a helper function.
    // ===========================
    pub async fn create_advertise_packet(&self) -> Result<DnsPacket, MdnsError> {
        let origin = {
            let origin_lock = self.origin.read().await;
            origin_lock
                .clone()
                .unwrap_or_else(|| "UnknownOrigin.local".to_string())
        };

        let services = self.registry.list_services_by_node(&origin).await;
        let mut packet = DnsPacket::new();
        // Set response flags.
        packet.flags = 0x8400;

        let local_ip = get_local_ipv4()
            .ok_or_else(|| MdnsError::Generic("Failed to get local IP".to_string()))?;

        if services.is_empty() {
            println!("(ADVERTISE) No local services to advertise.");
        } else {
            for service in services {
                println!("(ADVERTISE) Including service in packet: {:?}", service);

                // PTR record for service type.
                packet.answers.push(DnsRecord::PTR {
                    name: DnsName::new(&service.service_type).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ptr_name: DnsName::new(&service.id).unwrap(),
                });

                // SRV record pointing to the origin.
                packet.answers.push(DnsRecord::SRV {
                    name: DnsName::new(&service.id).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    priority: service.priority.unwrap_or(0),
                    weight: service.weight.unwrap_or(0),
                    port: service.port,
                    target: DnsName::new(&origin).unwrap(),
                });

                // A record with the local IP.
                packet.answers.push(DnsRecord::A {
                    name: DnsName::new(&service.origin).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ip: local_ip.octets(),
                });
            }
        }

        Ok(packet)
    }

    // ===========================
    // Sends a serialized DNS packet to the mDNS multicast address.
    // ===========================
    pub async fn send_packet(&self, packet: &DnsPacket) -> Result<(), MdnsError> {
        let bytes = packet.serialize();
        let multicast_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));

        self.socket
            .send_to(&bytes, multicast_addr)
            .await
            .map_err(MdnsError::NetworkError)?;

        Ok(())
    }

    // ===========================
    // Periodically sends out queries for a given service type.
    // - Uses backoff intervals and debouncing logic.
    // ===========================
    pub async fn periodic_query(&self, service_type: &str) {
        loop {
            let current_query_interval = self.backoff_interval_query.load(Ordering::Relaxed);

            let mut packet = DnsPacket::new();
            // Standard query flags (all bits cleared).
            packet.flags = 0x0000;
            packet.questions.push(crate::DnsQuestion {
                qname: DnsName::new(service_type).unwrap(),
                qtype: 12, // PTR record query.
                qclass: 1,
            });

            if let Err(err) = self.send_packet(&packet).await {
                eprintln!("(QUERY) Failed to send periodic query: {:?}", err);
            } else {
                println!(
                    "(QUERY) Periodic query sent for service type: {} (interval: {}s)",
                    service_type, current_query_interval
                );
            }

            self.adjust_backoff_state().await;

            tokio::time::sleep(Duration::from_secs(current_query_interval)).await;
        }
    }

    // ===========================
    // Advertises local services at adaptive intervals.
    // - Runs as a background task.
    // - Adjusts backoff state dynamically after each advertisement.
    // ===========================
    pub async fn advertise_services(self: Arc<Self>) -> Result<(), MdnsError> {
        tokio::spawn(async move {
            loop {
                {
                    let state = self.backoff_state.lock().await.clone();
                    let current_interval = self.backoff_interval_advertise.load(Ordering::Relaxed);

                    println!(
                        "(ADVERTISE) Current state: {:?}, Interval: {}s",
                        state, current_interval
                    );
                }

                if let Ok(packet) = self.create_advertise_packet().await {
                    if !packet.answers.is_empty() {
                        if let Err(err) = self.send_packet(&packet).await {
                            eprintln!("(ADVERTISE) Failed to send: {:?}", err);
                            return Err::<(), MdnsError>(err);
                        } else {
                            println!("(ADVERTISE) Sent mDNS advertisement.");
                        }
                    }
                } else {
                    eprintln!("(ADVERTISE) Failed to create packet.");
                    return Err(MdnsError::Generic("Failed to create mDNS packet".to_string()));
                }

                // Adjust backoff state dynamically.
                self.adjust_backoff_state().await;

                tokio::time::sleep(Duration::from_secs(
                    self.backoff_interval_advertise.load(Ordering::Relaxed),
                ))
                .await;
            }
        });

        Ok(())
    }

    // ===========================
    // Listens for incoming mDNS packets and dispatches them to the appropriate handler.
    // - Differentiates between query and response packets.
    // ===========================
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

    // ===========================
    // Periodically prints the current node registry.
    // ===========================
    pub async fn print_node_registry(&self) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let nodes = self.registry.list_nodes().await;
            println!("(NODE REGISTRY) Nodes: {:?}", nodes);
        }
    }

    // ===========================
    // Adjusts the backoff intervals based on the current backoff state.
    // - Supports Normal, Backoff, Recovery, and Stable states.
    // - Ensures that the query interval is not more than twice the advertise interval.
    // ===========================
    pub async fn adjust_backoff_state(&self) {
        let state = self.backoff_state.lock().await;
        let current_advertise_interval = self.backoff_interval_advertise.load(Ordering::Relaxed);
        let current_query_interval = self.backoff_interval_query.load(Ordering::Relaxed);

        match *state {
            BackoffState::Normal => {
                self.backoff_interval_advertise.store(5, Ordering::Relaxed);
                self.backoff_interval_query.store(5, Ordering::Relaxed);
            }
            BackoffState::Backoff => {
                let new_advertise_interval = (current_advertise_interval as f64 * 1.5).min(60.0) as u64;
                let new_query_interval = (current_query_interval as f64 * 1.5).min(60.0) as u64;
                self.backoff_interval_advertise.store(new_advertise_interval, Ordering::Relaxed);
                self.backoff_interval_query.store(new_query_interval, Ordering::Relaxed);
            }
            BackoffState::Recovery => {
                let new_advertise_interval = (current_advertise_interval as f64 / 1.5).max(5.0) as u64;
                let new_query_interval = (current_query_interval as f64 / 1.5).max(5.0) as u64;
                self.backoff_interval_advertise.store(new_advertise_interval, Ordering::Relaxed);
                self.backoff_interval_query.store(new_query_interval, Ordering::Relaxed);
            }
            BackoffState::Stable => {
                self.backoff_interval_advertise.store(10, Ordering::Relaxed);
                self.backoff_interval_query.store(10, Ordering::Relaxed);
            }
        }

        let adjusted_query_interval = self.backoff_interval_query.load(Ordering::Relaxed);
        let adjusted_advertise_interval = self.backoff_interval_advertise.load(Ordering::Relaxed);

        if adjusted_query_interval > 2 * adjusted_advertise_interval {
            self.backoff_interval_query
                .store(2 * adjusted_advertise_interval, Ordering::Relaxed);
        }

        println!(
            "(BACKOFF) Adjusted state: {:?}, New advertise interval: {}s, New query interval: {}s",
            *state, adjusted_advertise_interval, adjusted_query_interval
        );
    }

    // ===========================
    // Runs the MdnsService by launching all main tasks:
    // - Advertisement, periodic query, listening, and registry printing.
    // ===========================
    pub async fn run(self: &Arc<Self>, query_service_type: String) {
        let advertise_service = Arc::clone(self);
        let query_service = Arc::clone(self);
        let listen_service = Arc::clone(self);
        let registry_service = Arc::clone(self);

        // Start adaptive advertisement in a background task.
        tokio::spawn(advertise_service.clone().advertise_services());

        // Start adaptive periodic query.
        tokio::spawn(async move {
            query_service
                .periodic_query(&query_service_type)
                .await;
        });

        // Start the listen loop.
        tokio::spawn(async move {
            if let Err(err) = listen_service.listen().await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        // Periodically print the node registry.
        tokio::spawn(async move {
            registry_service.print_node_registry().await;
        });
    }

    // ===========================
    // Processes an incoming response packet.
    // - Handles A records (for node IP discovery) and SRV records (for service discovery).
    // - Updates the registry and emits events accordingly.
    // ===========================
    pub async fn process_response(&self, packet: &DnsPacket, src: &SocketAddr) {
        println!("Packet : {:?}", packet);

        // If the source is IPv4.
        if let SocketAddr::V4(src_addr) = src {
            for answer in &packet.answers {
                match answer {
                    // Handle A records to discover node IP addresses.
                    DnsRecord::A { name, ip, ttl } => {
                        let ip_address = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        println!(
                            "(DISCOVERY) Discovered node: {} -> {} <=> {}",
                            name,
                            ip_address,
                            src_addr.ip()
                        );

                        // Update or add the node to the registry.
                        if let Err(e) = self
                            .add_node_to_registry(
                                &name.to_string(),
                                &src_addr.ip().to_string(),
                                Some(*ttl),
                            )
                            .await
                        {
                            eprintln!("(DISCOVERY) Failed to add node: {:?}", e);
                        }

                        // Send a discovery event.
                        let _ = self
                            .event_sender
                            .send(MdnsEvent::Discovered(answer.clone()));
                    }

                    // Handle SRV records to discover services.
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

                        let srv_id = name.to_string();
                        let srv_origin = target.to_string().trim_end_matches('.').to_string();

                        let service_record = ServiceRecord {
                            id: srv_id.clone(),
                            service_type: extract_service_type(&srv_id),
                            port: *port,
                            ttl: Some(*ttl),
                            origin: srv_origin.clone(),
                            priority: Some(*priority),
                            weight: Some(*weight),
                            node_id: srv_origin.clone(),
                        };

                        // Add the service to our registry.
                        if let Err(e) = self.registry.add_service(service_record.clone()).await {
                            eprintln!("(DISCOVERY) Failed to add service: {:?}", e);
                        } else {
                            // Link the service to the node.
                            if let Err(e) = self.link_service_to_node(&service_record).await {
                                eprintln!("(DISCOVERY) Failed to link service to node: {:?}", e);
                            }
                        }

                        let _ = self
                            .event_sender
                            .send(MdnsEvent::Discovered(answer.clone()));
                    }
                    _ => {}
                }
            }
        }
        let updated_nodes = self.registry.list_nodes().await;
        println!("(REGISTRY) Current nodes: {:?}", updated_nodes);
    }

    // ===========================
    // Processes an incoming query packet.
    // - Debounces duplicate queries.
    // - Searches for matching services in the registry.
    // - Batches responses with a slight delay.
    // ===========================
    pub async fn process_query(&self, packet: &DnsPacket, src: &SocketAddr) {
        let mut cache = self.query_cache.lock().await;
        let now = current_timestamp();

        for question in &packet.questions {
            if question.qtype == 12 && question.qclass == 1 {
                let requested_service = question.qname.labels.join(".");

                // Debounce check: Ignore duplicate queries received within 500ms.
                if let Some(last_time) = cache.get(&requested_service) {
                    if now - *last_time < 500 {
                        println!(
                            "(DEBOUNCE) Ignoring duplicate query for {}",
                            requested_service
                        );
                        continue;
                    }
                }

                // Update query timestamp.
                cache.insert(requested_service.clone(), now);

                println!("Requested Service : {}", requested_service);
                let all_services = self.registry.list_services().await;

                // Find services whose IDs end with the requested service name.
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

                // Build DNS answers for each matching service.
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

                // Introduce a slight delay (200ms) to batch responses.
                let response_clone = response_packet.clone();
                let socket = Arc::clone(&self.socket); // Clone socket reference.
                let multicast_addr =
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if let Err(err) = socket
                        .send_to(&response_clone.serialize(), multicast_addr)
                        .await
                    {
                        eprintln!("(QUERY->RESP) Failed to send response: {:?}", err);
                    }
                });
            }
        }
    }

    // ===========================
    // Adds or updates a node in the registry based on the provided id and IP address.
    // - Checks for IP conflicts.
    // - Updates existing nodes or creates a new one.
    // ===========================
    async fn add_node_to_registry(
        &self,
        id: &str,
        ip_address: &str,
        ttl: Option<u32>,
    ) -> Result<(), MdnsError> {
        let normalized_id = id.trim_end_matches('.').to_string();
        let ip_address = ip_address.to_string();

        let mut nodes = self.registry.list_nodes().await;

        // Check for IP conflicts.
        if let Some(conflict) = nodes
            .iter()
            .find(|n| n.ip_address == ip_address && n.id != normalized_id)
        {
            return Err(MdnsError::Generic(format!(
                "IP conflict: {} is already assigned to {}",
                ip_address, conflict.id
            )));
        }

        // Update the node if it already exists.
        if let Some(existing_node) = nodes.iter_mut().find(|n| n.id == normalized_id) {
            if existing_node.ip_address != ip_address {
                existing_node.ip_address = ip_address.clone();
                existing_node.ttl = ttl;
                // Re-save the updated node.
                self.registry
                    .add_node(existing_node.clone())
                    .await
                    .map_err(|e| MdnsError::Generic(e.to_string()))?;
            }
        } else {
            // Create and add a new node.
            println!(
                "(DISCOVERY) Adding new node: {} with IP {}",
                normalized_id, ip_address
            );

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

/// ===========================
/// Helper: Retrieves the local IPv4 address (e.g. 192.168.x.x).
/// ===========================
fn get_local_ipv4() -> Option<Ipv4Addr> {
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

/// ===========================
/// Helper: Extracts the service type from an SRV record's name.
/// For example, if `srv_id = "MyLaptop.local._myDefault._tcp.local."`,
/// this function returns `_myDefault._tcp.local.`.
/// ===========================
fn extract_service_type(srv_id: &str) -> String {
    // A simple approach: find the first occurrence of "._" and return the remainder.
    if let Some(pos) = srv_id.find("._") {
        return srv_id[pos + 1..].to_string();
    }
    // Fallback: return the full string.
    srv_id.to_string()
}

/// ===========================
/// Helper: Returns the current timestamp in milliseconds.
/// ===========================
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}
