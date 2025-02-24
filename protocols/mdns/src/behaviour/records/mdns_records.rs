use serde::{Serialize, Deserialize};
use std::time::{SystemTime, Duration};
use registry::Record;
use std::fmt;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: String,
    pub service_type: String,
    pub port: u16,
    pub ttl: Option<u32>,
    pub origin: String,
    pub priority: Option<u16>,
    pub weight: Option<u16>,
    pub node_id: String, // New field linking the service to the node
}

impl Record for ServiceRecord {
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn expires_at(&self) -> Option<SystemTime> {
        self.ttl.map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
    }
}
impl fmt::Display for ServiceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceRecord {{ id: {}, service_type: {}, port: {}, ttl: {:?}, origin: {}, priority: {:?}, weight: {:?}, node_id: {} }}",
            self.id,
            self.service_type,
            self.port,
            self.ttl,
            self.origin,
            self.priority,
            self.weight,
            self.node_id
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,
    pub ip_addresses: Vec<String>,
    pub ttl: Option<u32>,
    pub services: Vec<String>,
}


impl Record for NodeRecord {
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn expires_at(&self) -> Option<SystemTime> {
        self.ttl
            .map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
    }
}
