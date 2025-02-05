# Nautilus Negotiation Protocol

The `nautilus_negotiation` module provides a **flexible negotiation framework** for resolving **compatibility between clients and servers**. It allows structured decision-making by applying **various negotiation strategies**, making it ideal for scenarios like:
- **Cipher suite selection**
- **Compression algorithm negotiation**
- **Feature selection in distributed systems**

Built in **Rust**, this module is fully **asynchronous** and **modular**, ensuring high performance and adaptability.

---

## 🌟 Features

### 🔄 **Flexible Negotiation Strategies**
- **Client-Preferred** – Prioritizes client-preferred choices.
- **Server-Preferred** – Server dictates the selection.
- **Same Footing** – Ensures equal weighting in the negotiation process.
- **First Match** – Picks the first compatible item.
- **Weighted Strategy** – Balances both client & server weights.

### ⚡ **Event-Driven & Efficient**
- **Context-aware** negotiations prevent mismatched selections.
- **Priority-based selection** ensures optimal compatibility.
- **Error-handling built-in** (e.g., `NoCompatibleItems`).

### 🏗 **Modular Design**
- **Plug-and-play strategy implementations**.
- **Custom negotiation logic** via trait-based extension.

---

## 🏛 **Architecture Overview**

This module consists of the following core components:

### 1️⃣ **Traits**
- **`Negotiable`** – Defines how items interact.
- **`NegotiationStrategy`** – Enables different negotiation policies.

### 2️⃣ **Negotiation Context**
- **`NegotiationContext`** – Defines what items are available for selection.
- Ensures that **both client and server contexts** are compatible.

### 3️⃣ **Negotiation Engine**
- **`negotiate_with_strategy`** – Handles negotiation logic.
- Uses **priority-based selection** to choose the best match.

### 4️⃣ **Error Handling**
- **`NegotiationError`** – Manages errors like:
  - **NoCompatibleItems** – No valid selection found.
  - **InvalidContext** – Context does not support negotiation.

---

# ⚠ Limitations
- Requires Implementations – Types must implement Negotiable and NegotiationContext.
- No Multi-Phase Negotiation – Doesn't support fallback strategies.
- Context Matching is Strict – Both parties must have some common items.
#🎯 Future Improvements
- ✅ Add Multi-Phase Negotiation – Enable fallback logic.
- ✅ Support Dynamic Weights – Allow real-time priority adjustments.
- ✅ Cross-Network Negotiation – Allow remote context negotiation.

# 📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

# 🤝 Contributing
Contributions are welcome! Open an issue or submit a pull request with your improvements.

