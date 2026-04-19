# 🛡️ BPFense Lite

### eBPF Runtime Security Engine (AI + Behavioral Detection)

BPFense Lite is a **lightweight, high-performance runtime security engine** built using **eBPF, rule-based detection, and AI-assisted anomaly analysis**.

It focuses on a **minimal, fast, and production-relevant detection core**—designed to operate with **low overhead while maintaining real-time threat visibility and response**.

> ⚡ Built as a practical system to demonstrate **kernel observability, runtime detection, and security engineering at scale**

---

## 🚀 Why BPFense Lite

Most runtime security tools become **heavy and complex**, impacting performance.

**BPFense Lite takes the opposite approach:**

* Minimal core
* Deterministic detection pipeline
* Real-time response
* Designed to scale without adding latency

---

## 🎥 Demo (Full System Vision)

This demo shows the **complete BPFense architecture**, including advanced detection and AI pipeline:

👉 https://www.youtube.com/shorts/X7cHbR0-Am4

> Note: This repository contains the **Lite (core) version**, focused on detection fundamentals.

---

## 🧠 What This Project Demonstrates

* eBPF-based **kernel-level observability**
* Runtime event collection (process, network)
* **Behavioral detection using temporal correlation**
* Hybrid detection (**rules + AI scoring**)
* **Real-time response system** (kill / alert)
* Kubernetes-aware monitoring (pod-level context)

---

## ⚡ Core Features

* ⚡ **Low-overhead eBPF monitoring**
* 🔍 **Runtime + network event visibility**
* 🧠 **Behavioral detection via event correlation**
* 🤖 **AI-assisted anomaly scoring**
* 🚨 **Escalation-based detection logic**
* ☸️ **Kubernetes pod awareness**
* 🔥 **Automated response (kill pod, alert)**

---

## 🧠 Detection Approach

BPFense Lite uses a **layered detection model**:

1. **Event Collection (eBPF)**

   * Syscalls, process execution, network activity

2. **Feature Extraction**

   * Normalize events into structured signals

3. **Detection Engines**

   * Rule-based detection (fast, deterministic)
   * AI-based scoring (behavioral anomalies)

4. **Correlation Layer**

   * Detects **multi-stage attacks using temporal relationships**

5. **Decision Engine**

   * Escalates based on repeated or high-risk patterns

6. **Response Engine**

   * Kill pod / alert / log

---

## 🧪 Example Output

```text
[AI][NORMAL] pod=test-bpfense-pod score=0.45

[AGENT] Escalation triggered (repeated anomalies)

[AI][HIGH] pod=test-bpfense-pod anomaly detected (rule=1)
[ACTION] KILL_POD pod=test-bpfense-pod
[ACTION] ALERT pod=test-bpfense-pod

[NETWORK] pod=coredns ns=kube-system -> 192.168.29.1:53 proto=UDP
[AI] analyzing network event...
```

👉 Full logs: `tests/test_logs.txt`

---

## 🧱 Architecture

```
eBPF Sensors (Kernel Space)
        ↓
Userspace Agent
        ↓
Feature Extraction
        ↓
 ┌───────────────┬───────────────┐
 │ Rule Engine   │ AI Engine     │
 └───────────────┴───────────────┘
        ↓
Decision Engine
        ↓
Response Engine (Kill / Alert)
```

---

## 🛠 Build & Run

### Requirements

* Linux (eBPF enabled kernel)
* clang / llvm
* libbpf
* gcc

### Build

```bash
make clean
make
```

### Run

```bash
sudo -E ./build/loader
```

---

## 📂 Project Structure

```
.
├── ebpf/             # Kernel-level sensors
├── userspace/        # Detection + response engine
├── ai-engine/        # ML inference logic
├── rules/            # Detection rules
├── include/          # Shared headers
├── scripts/          # Utilities
├── tests/            # Logs + test cases
├── Makefile
└── README.md
```

---

## 🔐 Security Notes

* Safe kernel interaction via eBPF (no kernel modules)
* Designed for **runtime detection, not prevention-only**
* Supports future **model verification and integrity checks**

---

## 🚀 Roadmap

* O(1) behavior state tracking (hash-map based)
* Advanced anomaly detection models
* Policy-driven response engine
* CLI interface (`monitor`, `train`, `analyze`)
* Full system open-source release

---

## ⚠️ Scope Clarification

This repository contains the **Lite detection core only**.

The full system (shown in demo) includes:

* Advanced behavioral modeling
* Distributed detection pipeline
* Extended AI capabilities

---

## 📬 Contact

**Anil Kumar**
📧 [anilkumar880@gmail.com](mailto:anilkumar880@gmail.com)
🔗 https://www.linkedin.com/in/anilkumar880/

---

## 📜 License

See `LICENSE` file.

---

## ⭐ Final Note

BPFense Lite is not just a demo—it’s a **foundation for building production-grade runtime security systems using eBPF**.

