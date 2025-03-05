// protocols/mdns/src/behaviour/service/listener.rs

use std::sync::Arc;

use tokio::time::Duration;

use crate::{DnsPacket, MdnsError};
use crate::behaviour::mdns_event::MdnsEvent;

use super::core_service::{MdnsService, current_timestamp, extract_service_type};
use crate::{
    DnsName, DnsRecord,
    behaviour::records::{NodeRecord, ServiceRecord},
};

use std::net::SocketAddr;

/// ===========================
/// Listens for incoming mDNS packets and dispatches them to the appropriate handler.
/// - Differentiates between query and response packets.
/// ===========================
pub async fn listen(service: Arc<MdnsService>) -> Result<(), MdnsError> {
    let mut buf = [0; 4096];
    loop {
        let (len, src) = service.socket
            .recv_from(&mut buf)
            .await
            .map_err(MdnsError::NetworkError)?;

        if let Ok(packet) = DnsPacket::parse(&buf[..len]) {
            let is_response = (packet.flags & 0x8000) != 0;
            if is_response {
                process_response(&service, &packet, &src).await;
            } else {
                process_query(&service, &packet, &src).await;
            }
        } else {
            eprintln!("(LISTEN) Failed to parse packet from {}", src);
        }
    }
}

/// ===========================
/// Processes an incoming response packet.
/// - Handles A records (for node IP discovery) and SRV records (for service discovery).
/// - Updates the registry and emits events accordingly.
/// ===========================
async fn process_response(service: &MdnsService, packet: &DnsPacket, src: &SocketAddr) {
    println!("Packet : {:?}", packet);

    // If the source is IPv4.
    if let SocketAddr::V4(_src_addr) = src {
        for answer in &packet.answers {
            match answer {
                // Handle A records to discover node IP addresses.
                DnsRecord::A { name, ip, ttl } => {
                    // IP from the DNS record:
                    let record_ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string();
                    
                    // The node name/ID
                    let node_id = name.to_string();
                    
                    println!(
                        "(DISCOVERY) Discovered node: {} with A record IP: {}",
                        node_id, record_ip
                    );
                    
                    // Fetch or create a NodeRecord with multiple IP support
                    let mut node = service.registry.get_node(&node_id).await.unwrap_or_else(|| NodeRecord {
                        id: node_id.clone(),
                        ip_addresses: Vec::new(),
                        ttl: Some(*ttl),
                        services: Vec::new(),
                    });
                    
                    // Add the new IP if not already present
                    if !node.ip_addresses.contains(&record_ip) {
                        println!("(DISCOVERY) Adding new IP {} to node {}", record_ip, node_id);
                        node.ip_addresses.push(record_ip.clone());
                    
                        if let Err(e) = service.registry.add_node(node.clone()).await {
                            eprintln!("(DISCOVERY) Failed to update node: {:?}", e);
                        }
                    } else {
                        println!(
                            "(DISCOVERY) Node {} already has IP {}. No update needed.",
                            node_id, record_ip
                        );
                    }
                    
                    // Fire a discovery event
                    let _ = service.event_handler.publish(MdnsEvent::Discovered(answer.clone()));
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
                    if let Err(e) = service.registry.add_service(service_record.clone()).await {
                        eprintln!("(DISCOVERY) Failed to add service: {:?}", e);
                    } else {
                        // Link the service to the node.
                        if let Err(e) = service.link_service_to_node(&service_record).await {
                            eprintln!("(DISCOVERY) Failed to link service to node: {:?}", e);
                        }
                    }

                    let _ = service.event_handler.publish(MdnsEvent::Discovered(answer.clone()));
                }
                _ => {}
            }
        }
    }
    let updated_nodes = service.registry.list_nodes().await;
    println!("(REGISTRY) Current nodes: {:?}", updated_nodes);
}

/// ===========================
/// Processes an incoming query packet.
/// - Debounces duplicate queries.
/// - Searches for matching services in the registry.
/// - Batches responses with a slight delay.
/// ===========================
async fn process_query(service: &MdnsService, packet: &DnsPacket, src: &SocketAddr) {
    let mut cache = service.query_cache.lock().await;
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
            let all_services = service.registry.list_services().await;

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
                let origin_lock = service.origin.read().await;
                origin_lock
                    .clone()
                    .unwrap_or_else(|| "UnknownOrigin.local".to_string())
            };

            // Build DNS answers for each matching service.
            for svc in matching_services {
                response_packet.answers.push(DnsRecord::PTR {
                    name: DnsName::new(&svc.service_type).unwrap(),
                    ttl: svc.ttl.unwrap_or(120),
                    ptr_name: DnsName::new(&svc.id).unwrap(),
                });

                response_packet.answers.push(DnsRecord::SRV {
                    name: DnsName::new(&svc.id).unwrap(),
                    ttl: svc.ttl.unwrap_or(120),
                    priority: svc.priority.unwrap_or(0),
                    weight: svc.weight.unwrap_or(0),
                    port: svc.port,
                    target: DnsName::new(&origin).unwrap(),
                });

                if let SocketAddr::V4(addr) = src {
                    response_packet.answers.push(DnsRecord::A {
                        name: DnsName::new(&origin).unwrap(),
                        ttl: svc.ttl.unwrap_or(120),
                        ip: addr.ip().octets(),
                    });
                }
            }

            // Introduce a slight delay (200ms) to batch responses.
            let response_clone = response_packet.clone();
            let socket = Arc::clone(&service.socket);
            let multicast_addr = SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(224, 0, 0, 251),
                5353,
            ));

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
