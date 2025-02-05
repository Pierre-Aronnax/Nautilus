#[cfg(test)]
mod tests {
    use mdns::current_timestamp;
    use mdns::{DnsName, DnsPacket, DnsQuestion, DnsRecord, MdnsService};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time;

    async fn setup_mdns_service() -> Arc<MdnsService> {
        MdnsService::new(
            Some("TestNode.local".to_string()),
            "_testservice._tcp.local.",
        )
        .await
        .expect("Failed to create MdnsService")
    }

    #[tokio::test]
    async fn test_register_default_node_service() {
        let service = setup_mdns_service().await;
        let result = service.register_default_node_service().await;
        assert!(result.is_ok());

        let node_services = service.registry.list_services().await;
        assert!(!node_services.is_empty());

        let default_service = node_services
            .iter()
            .find(|s| s.service_type == "_testservice._tcp.local.");
        assert!(default_service.is_some());
    }

    #[tokio::test]
    async fn test_register_local_service() {
        let service = setup_mdns_service().await;
        let result = service
            .register_local_service(
                "Service123.local".to_string(),
                "_custom._tcp.local.".to_string(),
                8080,
                Some(300),
                "TestNode.local".to_string(),
            )
            .await;
        assert!(result.is_ok());

        let service_registry = service.registry.list_services().await;
        let added_service = service_registry.iter().find(|s| s.id == "Service123.local");
        assert!(added_service.is_some());
        assert_eq!(added_service.unwrap().port, 8080);
    }

    #[tokio::test]
    async fn test_advertise_services() {
        let service = setup_mdns_service().await;
        let result = service.advertise_services().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_advertise_packet() {
        let service = setup_mdns_service().await;
        let packet = service
            .create_advertise_packet()
            .await
            .expect("Failed to create advertise packet");

        assert!(!packet.answers.is_empty());
        assert!(packet
            .answers
            .iter()
            .any(|record| matches!(record, DnsRecord::PTR { .. })));
        assert!(packet
            .answers
            .iter()
            .any(|record| matches!(record, DnsRecord::SRV { .. })));
    }

    #[tokio::test]
    async fn test_process_response() {
        let service = setup_mdns_service().await;
        let src = "192.168.1.100:5353".parse().unwrap();

        let packet = DnsPacket {
            id: 0,
            flags: 0x8400,
            questions: Vec::new(),
            answers: vec![
                DnsRecord::A {
                    name: DnsName::new("TestNode.local").unwrap(),
                    ttl: 300,
                    ip: [192, 168, 1, 100],
                },
                DnsRecord::SRV {
                    name: DnsName::new("TestService.local").unwrap(),
                    ttl: 300,
                    priority: 10,
                    weight: 10,
                    port: 8080,
                    target: DnsName::new("TestNode.local").unwrap(),
                },
            ],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        service.process_response(&packet, &src).await;
        let nodes = service.registry.list_nodes().await;
        assert!(!nodes.is_empty());
    }

    #[tokio::test]
    async fn test_process_query_debounce() {
        let service = setup_mdns_service().await;
        let src: std::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();

        let query_packet = DnsPacket {
            id: 1,
            flags: 0,
            questions: vec![DnsQuestion {
                qname: DnsName::new("_testservice._tcp.local.").unwrap(),
                qtype: 12,
                qclass: 1,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let query_cache_before = service.query_cache.lock().await.len();

        // Send first query (should be stored)
        service.process_query(&query_packet, &src).await;
        let query_cache_after_first = service.query_cache.lock().await.len();
        assert!(
            query_cache_after_first > query_cache_before,
            "First query should be stored."
        );

        // Send duplicate query immediately (should be ignored)
        service.process_query(&query_packet, &src).await;
        let query_cache_after_second = service.query_cache.lock().await.len();
        assert_eq!(
            query_cache_after_second, query_cache_after_first,
            "Duplicate query should be ignored due to debounce."
        );

        // **Force cache to expire**
        {
            let mut cache = service.query_cache.lock().await;
            let query_key = "_testservice._tcp.local.".to_string();
            cache.insert(query_key, current_timestamp() - 1000); // Manually expire debounce
        }

        // Wait a bit to simulate real conditions
        time::sleep(Duration::from_millis(600)).await;

        // Send query again (should be processed)
        service.process_query(&query_packet, &src).await;
        let query_cache_after_third = service.query_cache.lock().await.len();
        assert!(
            query_cache_after_third > query_cache_after_second,
            "Query should be processed after debounce expiry."
        );
    }
}
