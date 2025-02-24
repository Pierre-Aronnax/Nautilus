#[cfg(test)]
mod tests {
    use mdns::{NodeRecord, ServiceRecord, MdnsRegistry};
    use std::time::Duration;

    #[tokio::test]
    async fn test_add_and_retrieve_service() {
        let registry = MdnsRegistry::new();

        let service = ServiceRecord {
            id: "service1".to_string(),
            service_type: "http".to_string(),
            port: 8080,
            ttl: Some(5),
            origin: "local".to_string(),
            priority: Some(10),
            weight: Some(5),
            node_id: "node1".to_string(),
        };

        registry.add_service(service.clone()).await.unwrap();
        let retrieved = registry.get_service("service1").await;

        assert!(retrieved.is_some(), "Service should exist after being added");
        let retrieved_service = retrieved.unwrap();
        assert_eq!(retrieved_service.id, "service1");
        assert_eq!(retrieved_service.priority, Some(10));
        assert_eq!(retrieved_service.weight, Some(5));
        assert_eq!(retrieved_service.node_id, "node1");
    }

    #[tokio::test]
    async fn test_service_expiration() {
        let registry = MdnsRegistry::new();

        let service = ServiceRecord {
            id: "service2".to_string(),
            service_type: "https".to_string(),
            port: 443,
            ttl: Some(1),
            origin: "local".to_string(),
            priority: Some(10),
            weight: Some(5),
            node_id: "node2".to_string(),
        };

        registry.add_service(service).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        let retrieved = registry.get_service("service2").await;
        assert!(
            retrieved.is_none(),
            "Expired service should not be retrievable"
        );
    }

    #[tokio::test]
    async fn test_add_and_retrieve_node() {
        let registry = MdnsRegistry::new();

        let node = NodeRecord {
            id: "node1".to_string(),
            ip_addresses: vec!["192.168.1.1".to_string()],
            ttl: Some(10),
            services: vec!["service1".to_string()],
        };

        registry.add_node(node.clone()).await.unwrap();
        let retrieved = registry.get_node("node1").await;

        assert!(retrieved.is_some(), "Node should exist after being added");
        let retrieved_node = retrieved.unwrap();
        assert_eq!(retrieved_node.id, "node1");
        assert_eq!(retrieved_node.ip_addresses, vec!["192.168.1.1"]);
    }

    #[tokio::test]
    async fn test_node_expiration() {
        let registry = MdnsRegistry::new();

        let node = NodeRecord {
            id: "node2".to_string(),
            ip_addresses: vec!["192.168.1.2".to_string()], 
            ttl: Some(1),
            services: vec![],
        };

        registry.add_node(node).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        let retrieved = registry.get_node("node2").await;
        assert!(
            retrieved.is_none(),
            "Expired node should not be retrievable"
        );
    }

    #[tokio::test]
    async fn test_capacity_enforcement() {
        let registry = MdnsRegistry::new();

        // Insert 55 services to exceed capacity
        for i in 0..55 {
            let service = ServiceRecord {
                id: format!("service{}", i),
                service_type: "http".to_string(),
                port: 8000 + i as u16,
                ttl: None,
                origin: "local".to_string(),
                priority: Some(10),
                weight: Some(5),
                node_id: format!("node{}", i),
            };
            registry.add_service(service).await.unwrap();
        }

        let services = registry.list_services().await;
        assert_eq!(
            services.len(),
            50,
            "Service registry should enforce capacity limit"
        );
    }

    #[tokio::test]
    async fn test_mixed_expiration_and_capacity() {
        let registry = MdnsRegistry::new();

        let evictable_node = NodeRecord {
            id: "evictable_node".to_string(),
            ip_addresses: vec!["192.168.1.100".to_string()],
            ttl: Some(1),
            services: vec!["service_evict".to_string()],
        };

        let new_node = NodeRecord {
            id: "new_node".to_string(),
            ip_addresses: vec!["192.168.1.101".to_string()],
            ttl: None,
            services: vec![],
        };

        // First node with short TTL, so it expires
        registry.add_node(evictable_node).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second node should remain
        registry.add_node(new_node.clone()).await.unwrap();

        let nodes = registry.list_nodes().await;
        assert!(
            nodes.iter().any(|n| n.id == "new_node"),
            "New node should exist"
        );
        assert!(
            !nodes.iter().any(|n| n.id == "evictable_node"),
            "Expired node should not exist"
        );
    }

    #[tokio::test]
    async fn test_insertion_on_full_registry() {
        let registry = MdnsRegistry::new();

        // Fill the registry with the maximum number of records (50)
        for i in 0..50 {
            let service = ServiceRecord {
                id: format!("service{}", i),
                service_type: "http".to_string(),
                port: 8000 + i as u16,
                ttl: None,
                origin: "local".to_string(),
                priority: Some(10),
                weight: Some(5),
                node_id: format!("node{}", i),
            };
            registry.add_service(service).await.unwrap();
        }

        // Add a new service record
        let new_service = ServiceRecord {
            id: "new_service".to_string(),
            service_type: "http".to_string(),
            port: 8081,
            ttl: None,
            origin: "local".to_string(),
            priority: Some(10),
            weight: Some(5),
            node_id: "new_node".to_string(),
        };
        registry.add_service(new_service.clone()).await.unwrap();

        // Check that the total number of records is still 50
        let services = registry.list_services().await;
        assert_eq!(
            services.len(),
            50,
            "Service registry should enforce capacity limit"
        );

        // Check that the new record was added
        assert!(
            services.iter().any(|s| s.id == "new_service"),
            "New service should be present in the registry"
        );

        // Check that the oldest record was evicted
        assert!(
            !services.iter().any(|s| s.id == "service0"),
            "Oldest service should be evicted from the registry"
        );
    }
}
