use mdns::MdnsService;
use std::sync::Arc;
use tokio::{signal, spawn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and initialize the mDNS service
    let mdns_service = Arc::new(MdnsService::new(
        Some("MyLaptop.local".to_string()),  // Node's local hostname
        "_mdnsnode._tcp.local",             // Default service type
    )
    .await?);

    // Spawn the mDNS service
    let mdns_clone = Arc::clone(&mdns_service);
    spawn(async move {
        mdns_clone.run("_myservice._http._tcp.local.".to_string()).await;
    });

    // Spawn a task to listen for mDNS events
    let mdns_clone_receiver = Arc::clone(&mdns_service);
    spawn(async move {
       // 1) Await the future to get the actual broadcast::Receiver:
let mut receiver = mdns_clone_receiver.get_event_receiver().await;

// 2) Now call receiver.recv().await in the loop:
while let Ok(event) = receiver.recv().await {
    println!("(EVENT) => {:?}", event);
}
    });

    // Wait for a termination signal (Ctrl-C)
    signal::ctrl_c().await?;
    println!("(MAIN) Shutdown signal received.");

    // Retrieve and print discovered nodes
    let nodes = mdns_service.registry.list_nodes().await;
    println!("Discovered nodes: {:?}", nodes);

    Ok(())
}
