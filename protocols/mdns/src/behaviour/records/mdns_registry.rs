// protocols\mdns\src\behaviour\records\mdns_registry.rs
use crate::behaviour::records::mdns_records::{NodeRecord, ServiceRecord};
use registry::{InMemoryRegistry, Registry, RegistryError};
use std::sync::Arc;
use crate::MdnsError;
/// Represents the mDNS registry for managing service and node records.
pub struct MdnsRegistry {
    service_registry: Arc<InMemoryRegistry<ServiceRecord>>,
    node_registry: Arc<InMemoryRegistry<NodeRecord>>,
}

impl MdnsRegistry {
    /// Creates a new `MdnsRegistry` with default configurations.
    /// Creates a new `MdnsRegistry` with default configurations.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            service_registry: Arc::new(InMemoryRegistry::new(50)),
            node_registry: Arc::new(InMemoryRegistry::new(50)),
        })
    }

    /// Adds a service record to the service registry.
    pub async fn add_service(&self, record: ServiceRecord) -> Result<(), RegistryError> {
        self.service_registry.add(record).await
    }

    /// Retrieves a service record by its ID.
    pub async fn get_service(&self, id: &str) -> Option<ServiceRecord> {
        self.service_registry.get(id).await
    }

    /// Lists all service records in the registry.
    pub async fn list_services(&self) -> Vec<ServiceRecord> {
        self.service_registry.list().await
    }

    /// Adds a node record to the node registry.
    pub async fn add_node(&self, record: NodeRecord) -> Result<(), RegistryError> {
        self.node_registry.add(record).await
    }

    /// Retrieves a node record by its ID.
    pub async fn get_node(&self, id: &str) -> Option<NodeRecord> {
        self.node_registry.get(id).await
    }

    /// Lists all node records in the registry.
    pub async fn list_nodes(&self) -> Vec<NodeRecord> {
        self.node_registry.list().await
    }


    /// Lists all services associated with a specific node.
    pub async fn list_services_by_node(&self, node_id: &str) -> Vec<ServiceRecord> {
        let services = self.list_services().await;
        services.into_iter()
            .filter(|service| service.node_id == node_id)
            .collect()
    }

}


impl From<RegistryError> for MdnsError {
    fn from(error: RegistryError) -> Self {
        MdnsError::Generic(error.to_string()) // Adjust this to fit your error structure
    }
}
