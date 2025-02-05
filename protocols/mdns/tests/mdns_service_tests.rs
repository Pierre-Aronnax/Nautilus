#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use mdns::{MdnsService,DnsRecord,DnsName,DnsPacket};
    async fn setup_mdns_service() -> Arc<MdnsService> {
        MdnsService::new(Some("TestNode.local".to_string()), "_testservice._tcp.local.")
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

        let default_service = node_services.iter().find(|s| s.service_type == "_testservice._tcp.local.");
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
        let packet = service.create_advertise_packet().await.expect("Failed to create advertise packet");

        assert!(!packet.answers.is_empty());
        assert!(packet.answers.iter().any(|record| matches!(record, DnsRecord::PTR { .. })));
        assert!(packet.answers.iter().any(|record| matches!(record, DnsRecord::SRV { .. })));
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
          additionals : Vec::new()
      };
      
      

        service.process_response(&packet, &src).await;
        let nodes = service.registry.list_nodes().await;
        assert!(!nodes.is_empty());
    }
}
