# Fault-Tolerant Quorum-Driven Infrastructure Orchestrator (FTQ-IO)

An enterprise-grade, zero-trust incident response and infrastructure automation tool designed to secure critical software components and system daemons against unauthorized lifecycle manipulation and cyberattacks. 

Inspired by the decentralized governance models of internet infrastructure—specifically the **ICANN Root Zone DNSSEC Key Signing Key (KSK) Ceremonies**—this system enforces a strict multi-party cryptographic authorization layer over host-level management subsystems.

---

## 1. Research & Theoretical Framework

### 1.1 Architectural Decentralization & The Myth of the "Internet Kill Switch"
Our preliminary study evaluated the structural resilience of the global **World Wide Web (WWW)** and the **Domain Name System (DNS)**. Popular myths suggest a unified "global team" can single-handedly restart or shut down the internet. Our research deconstructs this:
* **The Root Zone Reality**: The ICANN Trusted Community Representatives (TCRs) act as guardians of the cryptographic root. They do not operate a centralized server; instead, they maintain a decentralized web of trust (*Trust Anchor*) that validates DNSSEC signatures.
* **The Consensus Paradigm**: If a catastrophic corruption or cyberattack targets the core DNS root zone, these guardians use physical smartcards to rebuild the *Key Signing Key (KSK)*. The network remains up because millions of independent routing nodes (operating BGP and local caching) voluntarily agree to trust this verified cryptographic root.

### 1.2 Cryptographic Primitive: Shamir's Secret Sharing (M-of-N)
To bring this enterprise-level security down to individual server architectures, this tool implements **Shamir's Secret Sharing Scheme (SSSS)** over a finite field. 
* A master infrastructure token is wrapped in an authenticated **AES-256-GCM** envelope.
* The matching decryption key is split into \(N\) unique polynomial coordinates (shares).
* The target system or daemon becomes mathematically immutable to single actors: it requires a threshold quorum of \(M\) components to rebuild the key matrix via Lagrange polynomial interpolation. If an attacker compromises a sub-threshold number of admins, the asset remains securely quarantined.

### 1.3 Active Cyber Defense & Incident Response (IR)
Simple state recycling (restarting an infected service) during an active cyberattack is insufficient, as it often spawns the malicious payload immediately back into memory. This project integrates two foundational IR concepts:
1. **Immediate Host Containment (Quarantine)**: Breaks the attacker's Command and Control (C2) network loops by forcefully halting the compromised service.
2. **Sanitized Bootstrap**: Flushes volatile registries (such as local DNS resolver caches to mitigate poisoning) and resets service operational states before spawning clean execution threads.

---

## 2. Technical Architecture & Cross-Platform Mapping

The orchestrator abstracts low-level operating system system calls to ensure seamless deployments across hybrid infrastructure landscapes:

| Operating System | Isolation Layer Mechanism | Sanitized Bootstrap Track |
| :--- | :--- | :--- |
| **Windows Server** | `win32serviceutil.StopService` (SCM Hook) | `ipconfig /flushdns` & Service Initiation |
| **Linux (POSIX)** | `systemctl kill -s SIGKILL` (Kernel Signal) | `systemctl reset-failed` & `sync` Flush |

---

## 3. Installation & Dependency Configuration

Ensure Python 3.10+ is deployed on the host system.

### 3.1 Setup Environment
Clone this repository and provision the runtime requirements:
```bash
pip install -r requirements.txt
```

*Note: For Windows host deployments, ensure the terminal session has administrative privileges to allow interaction with the Service Control Manager (SCM).*

---

## 4. Operational Execution Guide (Step-by-Step)

The tool runs completely via command-line arguments, supporting production-ready automated automation playbooks.

### Step 4.1: Vault Initialization (Pre-Incident Preparation)
Generate the master encrypted cryptopackage and distribute the split polynomial tokens among your designated trusted infrastructure guardians. 

Run the following command to create a **3-of-5 threshold vault**:
```bash
python main_cli.py initialize --token "EMERGENCY_BACKBONE_KEY_VALIDATION_TOKEN" --threshold 3 --shares 5
```

**Expected Secure Output:**
```text
[SUCCESS] Cryptographic Vault Initialized.
Vault Payload (Save this securely): eyJub25jZSI6ICJBYkNkRWYiLCAiY2lwaGVydGV4dCI6ICJYeVpBMTIz..."

Distributed Guardian Keys:
  Key #1: 1-1a2b3c4d5e6f...
  Key #2: 2-2b3c4d5e6f7a...
  Key #3: 3-3c4d5e6f7a8b...
  Key #4: 4-4d5e6f7a8b9c...
  Key #5: 5-5e6f7a8b9c0d...
```
* **The Vault Payload** can be stored in standard config files or public logs.
* **The Guardian Keys** must be separated and assigned to different security operators (e.g., using physical hardware tokens or distinct secure vaults).

### Step 4.2: Simulating or Executing Emergency Recovery (During a Cyberattack)
When a core service (e.g., `nginx` on Linux or `Print Spooler` / `W3SVC` on Windows) is actively compromised or acting as an attack vector, invoke the `recover` routine.

The script will **immediately isolate the service** to stop the attack vector, and will only restore the infrastructure if the required threshold of keys is supplied:

```bash
python main_cli.py recover \
  --service "nginx" \
  --vault "eyJub25jZSI6ICJBYkNkRWYiLCAiY2lwaGVydGV4dCI6ICJYeVpBMTIz..." \
  --keys "1-1a2b3c4d5e6f..." "2-2b3c4d5e6f7a..." "3-3c4d5e6f7a8b..."
```

#### Scenario A: Insufficient Quorum Supplied (Unauthorized Attempt)
If a malicious actor or an insufficient number of admins attempt to cycle the environment using fewer than 3 keys:
```text
[*] Incident Response Active: Isolation step triggered for safety on target 'nginx'...
[+] Isolation confirmed. Analyzing presented cryptographic credentials...
[ACCESS DENIED] Cryptographic quorum verification failed. Insufficient or invalid keys.
[!] Security Alert: Service 'nginx' will remain isolated in quarantine.
```

#### Scenario B: Quorum Met (Successful Production Restoration)
When the minimum number of valid keys are presented together:
```text
[*] Incident Response Active: Isolation step triggered for safety on target 'nginx'...
[+] Isolation confirmed. Analyzing presented cryptographic credentials...
[+] Authorization validated successfully. Quorum met.
[SUCCESS] Service 'nginx' recovered and brought online cleanly.
```

---

## 5. Security Best Practices & Hardening
* **Key Storage**: Never store the distributed keys on the same physical host running the application daemon.
* **Privilege Least Access**: Ensure the orchestrator runs under a dedicated service account equipped with narrow, targeted `sudoers` configurations (for Linux) or specific SCM Access Control Rights (for Windows).
