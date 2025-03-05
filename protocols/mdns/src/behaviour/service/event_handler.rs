// protocols/mdns/src/behaviour/service/event_handler.rs

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use crate::MdnsEvent;

/// EventHandler: Manages event subscriptions and passes events through a pipeline.
pub struct EventHandler {
    event_sender: broadcast::Sender<MdnsEvent>,
    subscribers: Arc<RwLock<Vec<broadcast::Receiver<MdnsEvent>>>>,
}

impl EventHandler {
    /// Creates a new event handler with a broadcast channel.
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(100);
        Self {
            event_sender,
            subscribers: Arc::new(RwLock::new(vec![])),
        }
    }

    /// Subscribes a new receiver to the event stream.
    pub async fn subscribe(&self) -> broadcast::Receiver<MdnsEvent> {
        let receiver = self.event_sender.subscribe(); // Create a new subscription
        self.subscribers.write().await.push(receiver.resubscribe()); // Store subscription
        receiver
    }

    /// Publishes an event to all subscribers.
    pub async fn publish(&self, event: MdnsEvent) {
      let subscriber_count = self.event_sender.receiver_count();
      println!("(EVENT HANDLER) Publishing to {} subscribers", subscriber_count);
      
      if let Err(e) = self.event_sender.send(event.clone()) {
          eprintln!("(EVENT HANDLER) Failed to send event: {:?}", e);
      }
        self.clean_subscribers().await; // Remove inactive subscribers
    }

    /// Removes inactive subscribers safely.
    async fn clean_subscribers(&self) {
      let mut subscribers = self.subscribers.write().await;

      // Use `.retain_mut()` pattern
      let mut i = 0;
      while i < subscribers.len() {
          let is_active = match subscribers[i].try_recv() {
              Ok(_) => true,  // Active subscriber
              Err(broadcast::error::TryRecvError::Lagged(_)) => true, // Lagging but active
              Err(broadcast::error::TryRecvError::Closed) => false, // Remove disconnected subscriber
              Err(broadcast::error::TryRecvError::Empty) => true, // Active but no messages yet
          };

          if !is_active {
              subscribers.remove(i); // Remove inactive subscriber
          } else {
              i += 1; // Move to the next subscriber
          }
      }
  }


    /// Redirects events to an external event pipeline.
    pub async fn start_pipeline(&self, external_pipeline: Arc<dyn Fn(MdnsEvent) + Send + Sync>) {
        let mut receiver = self.subscribe().await;

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                external_pipeline(event);
            }
        });
    }
}
