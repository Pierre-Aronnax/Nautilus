  // core\src\traits\api_trait.rs
  use crate::api_error::GenericAPIError;
  use async_trait::async_trait;
  #[async_trait]
pub trait APITrait {
    async fn initialize(&self) -> Result<(), GenericAPIError>;
    async fn handle_request(&self, request: &str) -> Result<String, GenericAPIError>;
    async fn send_response(&self, response: &str) -> Result<(), GenericAPIError>;
    async fn subscribe(&self, topic: &str) -> Result<(), GenericAPIError>;
    async fn unsubscribe(&self, topic: &str) -> Result<(), GenericAPIError>;
    async fn shutdown(&self) -> Result<(), GenericAPIError>;
}