// core\src\traits\api_trait.rs
pub trait APITrait {
  /// Initializes the API service, setting up necessary configurations.
  fn initialize(&self) -> Result<(), String>;

  /// Handles incoming requests in a generic manner.
  /// 
  /// # Arguments
  /// * `request` - A generic request payload.
  fn handle_request(&self, request: &str) -> Result<String, String>;

  /// Sends a response based on a processed request.
  /// 
  /// # Arguments
  /// * `response` - The response payload to be sent.
  fn send_response(&self, response: &str) -> Result<(), String>;

  /// Subscribes to an event or data stream, useful for WebSockets/MQTT.
  /// 
  /// # Arguments
  /// * `topic` - The subscription topic or event name.
  fn subscribe(&self, topic: &str) -> Result<(), String>;

  /// Unsubscribes from a previously subscribed event or data stream.
  /// 
  /// # Arguments
  /// * `topic` - The subscription topic or event name.
  fn unsubscribe(&self, topic: &str) -> Result<(), String>;

  /// Shuts down the API service gracefully.
  fn shutdown(&self) -> Result<(), String>;
}
