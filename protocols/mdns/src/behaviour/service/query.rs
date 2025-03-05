// protocols/mdns/src/behaviour/service/query.rs

use std::sync::Arc;
use tokio::time::Duration;

use crate::DnsPacket;
use super::core_service::MdnsService;

/// ===========================
/// Periodically sends out queries for a given service type.
/// - Uses backoff intervals and debouncing logic.
/// ===========================
pub async fn periodic_query(service: Arc<MdnsService>, service_type: &str) {
    loop {
        let current_query_interval = service.backoff_interval_query.load(std::sync::atomic::Ordering::Relaxed);

        let mut packet = DnsPacket::new();
        // Standard query flags (all bits cleared).
        packet.flags = 0x0000;
        packet.questions.push(crate::DnsQuestion {
            qname: crate::DnsName::new(service_type).unwrap(),
            qtype: 12, // PTR record query.
            qclass: 1,
        });

        if let Err(err) = service.send_packet(&packet).await {
            eprintln!("(QUERY) Failed to send periodic query: {:?}", err);
        } else {
            println!(
                "(QUERY) Periodic query sent for service type: {} (interval: {}s)",
                service_type, current_query_interval
            );
        }

        // Adjust backoff
        service.adjust_backoff_state().await;

        tokio::time::sleep(Duration::from_secs(current_query_interval)).await;
    }
}
