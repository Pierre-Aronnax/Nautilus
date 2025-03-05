// protocols/mdns/src/behaviour/service/advertiser.rs

use std::sync::Arc;
use tokio::time::Duration;

use crate::{DnsPacket, MdnsError};
use super::core_service::MdnsService;
use super::socket::get_local_ipv4;

/// ===========================
/// Builds an mDNS advertisement packet containing PTR, SRV, and A records.
/// - Retrieves local services from the registry.
/// - Determines the local IP address using a helper function.
/// ===========================
async fn create_advertise_packet(service: &MdnsService) -> Result<DnsPacket, MdnsError> {
    let origin = {
        let origin_lock = service.origin.read().await;
        origin_lock
            .clone()
            .unwrap_or_else(|| "UnknownOrigin.local".to_string())
    };

    let services = service.registry.list_services_by_node(&origin).await;
    let mut packet = DnsPacket::new();
    // Set response flags.
    packet.flags = 0x8400;

    let local_ip = get_local_ipv4()
        .ok_or_else(|| MdnsError::Generic("Failed to get local IP".to_string()))?;

    if services.is_empty() {
        println!("(ADVERTISE) No local services to advertise.");
    } else {
        for svc in services {
            println!("(ADVERTISE) Including service in packet: {:?}", svc);

            // PTR
            packet.answers.push(crate::DnsRecord::PTR {
                name: crate::DnsName::new(&svc.service_type).unwrap(),
                ttl: svc.ttl.unwrap_or(120),
                ptr_name: crate::DnsName::new(&svc.id).unwrap(),
            });

            // SRV
            packet.answers.push(crate::DnsRecord::SRV {
                name: crate::DnsName::new(&svc.id).unwrap(),
                ttl: svc.ttl.unwrap_or(120),
                priority: svc.priority.unwrap_or(0),
                weight: svc.weight.unwrap_or(0),
                port: svc.port,
                target: crate::DnsName::new(&origin).unwrap(),
            });

            // A
            packet.answers.push(crate::DnsRecord::A {
                name: crate::DnsName::new(&svc.origin).unwrap(),
                ttl: svc.ttl.unwrap_or(120),
                ip: local_ip.octets(),
            });
        }
    }

    Ok(packet)
}

/// ===========================
/// Advertises local services at adaptive intervals.
/// - Runs as a background task.
/// - Adjusts backoff state dynamically after each advertisement.
/// ===========================
pub async fn advertise_services(service: Arc<MdnsService>) -> Result<(), MdnsError> {
    loop {
        {
            let state = service.backoff_state.lock().await.clone();
            let current_interval = service.backoff_interval_advertise.load(std::sync::atomic::Ordering::Relaxed);

            println!(
                "(ADVERTISE) Current state: {:?}, Interval: {}s",
                state, current_interval
            );
        }

        match create_advertise_packet(&service).await {
            Ok(packet) => {
                if !packet.answers.is_empty() {
                    if let Err(err) = service.send_packet(&packet).await {
                        eprintln!("(ADVERTISE) Failed to send: {:?}", err);
                        return Err(err);
                    } else {
                        println!("(ADVERTISE) Sent mDNS advertisement.");
                    }
                }
            }
            Err(e) => {
                eprintln!("(ADVERTISE) Failed to create packet. {}",e);
                return Err(MdnsError::Generic("Failed to create mDNS packet".to_string()));
            }
        }

        // Adjust backoff
        service.adjust_backoff_state().await;

        let interval = service.backoff_interval_advertise.load(std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
  