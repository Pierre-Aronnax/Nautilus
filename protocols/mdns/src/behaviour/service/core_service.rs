// protocols/mdns/src/behaviour/service/core_service.rs

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{self, Duration};

use crate::behaviour::back_off::BackoffState;
use crate::behaviour::records::{NodeRecord, ServiceRecord};
use crate::{
    DnsName, DnsPacket, DnsRecord, MdnsError, MdnsEvent,MdnsRegistry
};
use super::socket::setup_multicast_socket;
use super::advertiser;
use super::listener;
use super::query;
use super::event_handler::EventHandler;

/// ===========================
/// MdnsService: Represents the mDNS service,
/// handling registry management and network communication.
/// ===========================
pub struct MdnsService {
    pub socket: Arc<UdpSocket>,
    pub registry: Arc<MdnsRegistry>,
    // pub event_sender: broadcast::Sender<MdnsEvent>,
    pub event_handler: Arc<EventHandler>,
    pub origin: Arc<RwLock<Option<String>>>,
    pub default_service_type: String,
    pub query_cache: Arc<Mutex<HashMap<String, u64>>>,
    pub backoff_state: Arc<Mutex<BackoffState>>,
    pub backoff_interval_advertise: AtomicU64,
    pub backoff_interval_query: AtomicU64,
}

impl MdnsService {
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
        let socket = setup_multicast_socket().await?;
        let registry = MdnsRegistry::new();
        let event_handler = Arc::new(EventHandler::new());
        let service = Arc::new(Self {
            socket: Arc::new(socket),
            registry,
            event_handler,
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
    pub async fn get_event_receiver(&self) -> tokio::sync::broadcast::Receiver<MdnsEvent> {
        self.event_handler.subscribe().await
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

        let event = MdnsEvent::Discovered(DnsRecord::SRV {
            name: DnsName::new(&service.id).unwrap(),
            ttl: service.ttl.unwrap_or(120),
            priority: service.priority.unwrap_or(0),
            weight: service.weight.unwrap_or(0),
            port: service.port,
            target: DnsName::new(&service.origin).unwrap(),
        });

        self.event_handler.publish(event).await; // Notify listeners

        Ok(())
    }

    // ===========================
    // Links a given service record to its corresponding node record.
    // - If the node does not exist, a new one is created with a default IP.
    // - Otherwise, the service is added to the node's list if not already present.
    // ===========================
    pub async fn link_service_to_node(&self, service: &ServiceRecord) -> Result<(), MdnsError> {
        let node_id = service.node_id.trim_end_matches('.').to_string();

        let mut node_opt = self.registry.get_node(&node_id).await;
        if node_opt.is_none() {
            node_opt = Some(NodeRecord {
                id: node_id.clone(),
                ip_addresses: Vec::new(),
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
                let new_advertise_interval =
                    (current_advertise_interval as f64 / 1.5).max(5.0) as u64;
                let new_query_interval = (current_query_interval as f64 / 1.5).max(5.0) as u64;
                self.backoff_interval_advertise
                    .store(new_advertise_interval, Ordering::Relaxed);
                self.backoff_interval_query
                    .store(new_query_interval, Ordering::Relaxed);
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
        let advertiser_service = Arc::clone(self);
        let query_service = Arc::clone(self);
        let listener_service = Arc::clone(self);
        let registry_service = Arc::clone(self);

        // Start adaptive advertisement in a background task.
        tokio::spawn(async move {
            if let Err(e) = advertiser::advertise_services(advertiser_service).await {
                eprintln!("(ADVERTISE) Error: {:?}", e);
            }
        });

        // Start adaptive periodic query.
        tokio::spawn(async move {
            query::periodic_query(query_service, &query_service_type).await;
        });

        // Start the listen loop.
        tokio::spawn(async move {
            if let Err(err) = listener::listen(listener_service).await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        // Periodically print the node registry.
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(10)).await;
                let nodes = registry_service.registry.list_nodes().await;
                println!("(NODE REGISTRY) Nodes: {:?}", nodes);
            }
        });
    }

    /// ===========================
    /// Redirects events to an external event pipeline.
    /// ===========================
    pub async fn start_event_pipeline(&self, external_pipeline: Arc<dyn Fn(MdnsEvent) + Send + Sync>) {
        self.event_handler.start_pipeline(external_pipeline).await;
    }

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

/// ===========================
/// Helper: Extracts the service type from an SRV record's name.
/// For example, if `srv_id = "MyLaptop.local._myDefault._tcp.local."`,
/// this function returns `_myDefault._tcp.local.`.
/// ===========================
pub fn extract_service_type(srv_id: &str) -> String {
    // A simple approach: find the first occurrence of "._" and return the remainder.
    if let Some(pos) = srv_id.find("._") {
        return srv_id[pos + 1..].to_string();
    }
    // Fallback: return the full string.
    srv_id.to_string()
}
