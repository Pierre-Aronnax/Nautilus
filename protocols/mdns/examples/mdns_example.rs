// protocols\mdns\examples\mdns_example.rs
//! # Example: Using the Nautilus mDNS Service for Discovery and Advertisement
//!
//! This example demonstrates how to utilize the `MdnsService` from the `nautilus_mdns` crate
//! to discover and advertise services over the local network using the mDNS (Multicast DNS) protocol.
//!
//! The example covers the following functionalities:
//! - Initializing an mDNS service with a custom node name.
//! - Running the mDNS service to advertise and query for services.
//! - Listening for mDNS events.
//! - Handling shutdown signals and printing discovered nodes before exiting.

use mdns::MdnsService;
use std::sync::Arc;
use tokio::{signal, spawn};

/// Entry point of the asynchronous mDNS service example.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the mDNS service instance with:
    // - A node origin of "MyLaptop.local" (custom hostname).
    // - A default service type of "_mdnsnode._tcp.local." (compulsory for this implementation).
    let mdns_service = MdnsService::new(
        Some("MyLaptop.local".to_string()),  // Node's local hostname
        "_mdnsnode._tcp.local.",             // Default service type
    )
    .await?;

    // Wrap the service in an `Arc` (atomic reference counting) for thread-safe sharing across tasks.
    let mdns_service = Arc::new(mdns_service);

    // Clone the Arc to share the mDNS service instance across tasks
    let mdns_clone = Arc::clone(&mdns_service);
    spawn(async move {
        // Start the mDNS service to:
        // - Query for "_myservice._http._tcp.local." every 5 seconds.
        // - Advertise the service every 10 seconds.
        mdns_clone
            .run("_myservice._http._tcp.local.".to_string())
            .await;
    });

    // Get the event receiver to handle discovered mDNS events.
    let mut receiver = mdns_service.get_event_receiver();
    spawn(async move {
        while let Ok(event) = receiver.recv().await {
            // Print each received mDNS event to the console
            println!("(EVENT) => {:?}", event);
        }
    });

    // Wait for a termination signal (Ctrl-C) to gracefully shut down the service.
    signal::ctrl_c().await?;
    println!("(MAIN) Shutdown signal received.");

    // Once the service is shut down, retrieve and print the discovered nodes.
    let nodes = mdns_service.registry.list_nodes().await;
    println!("Discovered nodes: {:?}", nodes);

    Ok(())
}
