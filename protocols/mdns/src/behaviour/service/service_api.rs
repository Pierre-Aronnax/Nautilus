// protocols/mdns/src/behaviour/service/service_api.rs

use std::sync::Arc;
use crate::MdnsError;
use super::{
    core_service::MdnsService,
    advertiser,
    listener,
    query,
};
use tokio::time::{self, Duration};

/// MdnsRuntime: A high-level API that sets up and runs the entire mDNS flow.
///
/// Usage:
///   let runtime = MdnsRuntime::new(Some("MyHost.local".to_string()), "_myDefault._tcp.local");
///   runtime.start("_myservice._http._tcp.local").await;
///
/// This will spawn tasks for:
///   1) Advertising local services
///   2) Periodic queries
///   3) Listening for inbound mDNS packets
///   4) Printing the registry periodically
pub struct MdnsRuntime {
    pub service: Arc<MdnsService>,
}

impl MdnsRuntime {
    /// Create a new MdnsRuntime, which internally builds an MdnsService
    /// and registers a default node service.
    pub async fn new(
        origin: Option<String>,
        default_service_type: &str
    ) -> Result<Self, MdnsError> {
        let service = MdnsService::new(origin, default_service_type).await?;
        Ok(MdnsRuntime { service })
    }

    /// Start all background tasks: advertiser, query, listener, registry printing, etc.
    /// The `query_service_type` is the service type we want to discover, e.g. "_myservice._tcp.local".
    pub async fn start(&self, query_service_type: &str) {
        let service_advert = Arc::clone(&self.service);
        let service_query = Arc::clone(&self.service);
        let service_listener = Arc::clone(&self.service);

        // 1) Start advertisement
        tokio::spawn(async move {
            if let Err(e) = advertiser::advertise_services(service_advert).await {
                eprintln!("(ADVERTISE) Error: {:?}", e);
            }
        });

        // 2) Start periodic queries
        let query_service_type = query_service_type.to_string();
        tokio::spawn(async move {
            query::periodic_query(service_query, &query_service_type).await;
        });

        // 3) Start the listener loop
        tokio::spawn(async move {
            if let Err(err) = listener::listen(service_listener).await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        // 4) Periodically print the registry
        let reg_service = Arc::clone(&self.service);
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(10)).await;
                let nodes = reg_service.registry.list_nodes().await;
                println!("(NODE REGISTRY) Nodes: {:?}", nodes);
            }
        });
    }
}
