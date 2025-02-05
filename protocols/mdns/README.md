# Nautilus mDNS Protocol

The `nautilus_mdns` module is a lightweight, decentralized **Multicast DNS (mDNS)** service for local network discovery. Whether you're building **peer-to-peer applications**, **decentralized systems**, or **IoT networks**, this protocol makes it easy to **discover nodes and services** without a central registry.

This project is built with **Rust**, leveraging **Tokio** for async networking and **Socket2** for low-level multicast handling.

---

## 🌟 Features

### 🔎 **Service Discovery**
- Automatically **discovers** available services in the local network.
- Supports **periodic announcements** to ensure peers stay updated.

### 🖧 **Node Discovery**
- Dynamically registers and manages nodes in a **local subnet**.
- Updates node information when changes are detected.

### 📦 **Registry Management**
- Maintains a **local database** of services and nodes.
- Implements **TTL expiration** for stale records.
- **Optimized memory usage** with a capacity-limited registry.

### ⚡ **Event-Driven Design**
- Emits structured events to enable **reactive programming**.
- Events include:
  - **`Discovered`** – A new service or peer was found.
  - **`Updated`** – A service or node refreshed its TTL.
  - **`Expired`** – A stale record was removed.

### ❌ **Robust Error Handling**
- Handles **serialization/deserialization** errors.
- Manages **network failures** (e.g., multicast socket issues).
- Provides meaningful errors via **`MdnsError`**.

---

## 🏛 **Architecture Overview**

This protocol consists of the following core components:

### 1️⃣ **Packet Handling**
- **`DnsPacket`** – Constructs and parses mDNS messages.
- **`DnsRecord`** – Supports **A**, **PTR**, **SRV**, and **TXT** records.
- **`DnsName`** – Handles domain name parsing and formatting.

### 2️⃣ **mDNS Service**
- **`MdnsService`**
  - Manages the **multicast UDP socket**.
  - Sends periodic **queries and advertisements**.
  - Listens for incoming **mDNS responses**.

### 3️⃣ **Registry Management**
- **`MdnsRegistry`**
  - Stores **services and nodes** with TTL enforcement.
  - Supports **retrieval, listing, and expiration** of records.

### 4️⃣ **Event & Error Handling**
- **`MdnsEvent`** – Defines structured **mDNS lifecycle events**.
- **`MdnsError`** – Captures network, packet, and registry errors.

---

# 🚀 Usage

### 1️⃣ Initialize and Run mDNS Service

```rust
use nautilus_mdns::MdnsService;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mdns_service = MdnsService::new(Some("MyNode.local".to_string()), "_http._tcp.local.")
        .await
        .expect("Failed to initialize mDNS service");

    let mdns_service = Arc::new(mdns_service);

    // Start periodic queries and advertisements
    mdns_service.run("_http._tcp.local.".to_string(), 10, 30).await;
}
```

##@ 2️⃣ Registering a Local Service
```rust
let mdns_service = MdnsService::new(Some("MyNode.local".to_string()), "_http._tcp.local.")
    .await
    .expect("Failed to initialize mDNS service");

mdns_service
    .register_local_service(
        "my-service.local".to_string(),
        "_http._tcp.local".to_string(),
        8080,
        Some(120),
        "MyNode.local".to_string(),
    )
    .await
    .expect("Failed to register local service");
```


### 3️⃣ Listening for Incoming Queries
```rust
mdns_service.listen().await.expect("Failed to start mDNS listener");
```

### 4️⃣ Processing mDNS Events
```rust
match event {
    MdnsEvent::Discovered(record) => println!("Discovered: {:?}", record),
    MdnsEvent::Updated(record) => println!("Updated: {:?}", record),
    MdnsEvent::Expired(record) => println!("Expired: {:?}", record),
    _ => {}
}
```

# ⚠ Limitations
- 🌐 Local Network Only – Works only on local subnets due to mDNS constraints.
- 🔐 No Authentication – Services and nodes are added without verification.
- 📡 Multicast Overhead – Large networks may experience higher traffic.
# 🎯 Future Improvements
- ✅ Authentication & Security – Add service validation and cryptographic signatures.
- 🌍 Cross-Subnet Discovery – Implement relay-based discovery across networks.
- 📊 Metrics & Monitoring – Collect performance data and network statistics.
- 🤝 Gossip Protocol – Synchronize large-scale registries across nodes.

# 📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

# 🤝 Contributing
Contributions are welcome! Open an issue or submit a pull request with your improvements. 