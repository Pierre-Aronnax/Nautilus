# Nautilus Kademlia (KAD) Distributed Hash Table (DHT)

The `nautilus_kad` module provides a **fully decentralized routing protocol** based on **Kademlia (KAD)**. It is designed to efficiently store and locate nodes in a **peer-to-peer (P2P) network**, making it ideal for:
- **Decentralized file sharing**
- **Blockchain networks**
- **Decentralized identity & communication**

This module is built in **Rust**, leveraging **Tokio** for asynchronous networking and **UDP** for lightweight communication.

---

## 🌟 Features

### 🗺 **Decentralized Node Lookup**
- Uses **XOR distance metric** to find the **closest** nodes.
- Implements **iterative node lookup** for efficient routing.
- Supports **bootstrapping into an existing network**.

### ⚡ **Efficient Routing & Storage**
- Implements **160-bit node IDs** for structured routing.
- **Routing table management** with **bucket-based node storage**.
- Supports **network maintenance** and **self-healing**.

### 🔄 **Kademlia Protocol Support**
- **Ping/Pong** – Check node availability.
- **FindNode** – Locate the closest nodes to a target ID.
- **NodeFound** – Respond to node queries.
- **Store & Retrieve** – (Future extension) Store & retrieve values from the DHT.

### 🛠 **Built-in Error Handling**
- Gracefully handles **unresponsive nodes**.
- Implements **timeouts** to avoid infinite lookups.
- Provides structured errors for **better debugging**.

---

## 🏛 **Architecture Overview**

This module consists of several key components:

### **1️⃣ Node & Routing**
- **`Node`** – Represents a Kademlia node (`id` + `IP address`).
- **`RoutingTable`** – Stores nodes in **buckets**, enabling efficient lookups.
- **`xor_distance`** – Calculates XOR distance for **closest-node selection**.

### **2️⃣ Kademlia Protocol**
- **`KadProtocol`** – Core logic for handling Kademlia operations.
- **`KadMessage`** – Defines Kademlia messages (`Ping`, `FindNode`, etc.).
- **`Bootstrapper`** – Manages the **initial network entry**.

### **3️⃣ Communication**
- **`UdpConnection`** – Handles **UDP-based message passing**.
- **`query_find_node`** – Sends queries to locate **closest nodes**.

---


# ⚠ Limitations
- No Data Storage Yet – Currently supports node lookup only (Store/Retrieve operations not implemented yet).
- UDP-Based – Not optimized for TCP-based communications.
- Fixed Bucket Sizes – Routing table is limited to 160 buckets.
# 🎯 Future Improvements
- ✅ Support for Storing & Retrieving Values – Implement Store and ValueFound operations.
- ✅ Optimize Routing Table – Improve node eviction and bucket management.
- ✅ Add TCP Support – Extend support beyond UDP for better reliability.
# 📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

# 🤝 Contributing
Contributions are welcome! Open an issue or submit a pull request with your improvements.