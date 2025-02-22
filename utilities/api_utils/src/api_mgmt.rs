// utilities\api_utils\src\api_mgmt.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::api_trait::APITrait;
use crate::api_error::GenericAPIError;

/// Root API Service Manager
#[derive(Clone)]
pub struct RootAPIService {
    services: Arc<Mutex<HashMap<String, Arc<dyn APITrait + Send + Sync>>>>,
}

impl RootAPIService {
    pub fn new() -> Self {
        Self {
            services: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register_service<S: APITrait + Send + Sync + 'static>(
        &self, 
        name: &str, 
        svc: S
    ) -> Result<(), GenericAPIError> {
        let mut map = self.services.lock().await;
        map.insert(name.to_string(), Arc::new(svc));
        Ok(())
    }

    pub async fn initialize_all(&self) -> Result<(), GenericAPIError> {
        let map = self.services.lock().await;
        for (name, svc) in map.iter() {
            println!("Initializing service: {}", name);
            svc.initialize().await?;
        }
        Ok(())
    }

    pub async fn shutdown_all(&self) -> Result<(), GenericAPIError> {
        let map = self.services.lock().await;
        for (name, svc) in map.iter() {
            println!("Shutting down service: {}", name);
            svc.shutdown().await?;
        }
        Ok(())
    }

    pub async fn get_service(&self, name: &str) 
        -> Option<Arc<dyn APITrait + Send + Sync>>
    {
        let map = self.services.lock().await;
        map.get(name).cloned()
    }
}
