# 🛡️ CloudGuard AI

> **Autonomous Cloud Security Incident Response System**
> Built for the **lablab.ai Band of Agents Hackathon**

CloudGuard AI is a fully autonomous, event-driven multi-agent system that detects, evaluates, and remediates cloud security threats in real-time — without human intervention. It ingests raw AWS WAF logs, orchestrates 4 specialized AI agents through the **Band API**, and auto-generates deployable **AWS WAFv2 Terraform** code to block attackers.

---

## 🏗️ Architecture Overview

```
Raw WAF Log Input
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│               CloudGuard Orchestrator                   │
│              (band_layer/state_manager.py)              │
└────────┬────────────────────────────────────────────────┘
         │
         ▼ Stage 1
┌─────────────────────┐        ┌──────────────────────┐
│  ThreatHunterAgent  │──PUSH─▶│   Band API Hub       │
│  (Forensic Parser)  │        │  cloudguard.state    │
└─────────┬───────────┘        │  .FORENSICS          │
          │ forensics JSON      └──────────────────────┘
          ▼ Stage 2
┌─────────────────────┐        ┌──────────────────────┐
│ PolicyCheckerAgent  │──PUSH─▶│   Band API Hub       │
│ (Zero-Trust Policy) │        │  cloudguard.state    │
└─────────┬───────────┘        │  .POLICY_CHECK       │
          │ PASSED / FAILED     └──────────────────────┘
          │
     ┌────┘ (HALT if FAILED)
     ▼ Stage 3
┌─────────────────────┐        ┌──────────────────────┐
│ CloudOpsRunnerAgent │──PUSH─▶│   Band API Hub       │
│  (Terraform IaC)    │        │  cloudguard.state    │
└─────────┬───────────┘        │  .IAC_GENERATION     │
          │ Terraform HCL       └──────────────────────┘
          ▼ Stage 4
┌─────────────────────┐        ┌──────────────────────┐
│   ValidatorAgent    │──PUSH─▶│   Band API Hub       │
│  (CIDR Safety Audit)│        │  cloudguard.state    │
└─────────┬───────────┘        │  .VALIDATION         │
          │                     └──────────────────────┘
          ▼
   Final Pipeline Report
   (COMPLETED / HALTED / FAILED)
```

---

## 🤖 Agent Roster

| Agent | File | Role | LLM Temp |
|---|---|---|---|
| **ThreatHunterAgent** | `core_agents/threat_hunter.py` | Parses raw WAF logs → structured forensic JSON | `0.2` |
| **PolicyCheckerAgent** | `core_agents/policy_checker.py` | Enforces zero-trust policies → PASSED/FAILED decision | `0.2` |
| **CloudOpsRunnerAgent** | `core_agents/cloud_ops_runner.py` | Generates AWS WAFv2 Terraform HCL code | `0.1` |
| **ValidatorAgent** | `core_agents/validator.py` | CIDR safety auditor — blocks `/0` and `/8` blocks | `0.0` |

All agents are powered by **CrewAI** using `groq/llama-3.3-70b-versatile`.

---

## 🔄 Pipeline Flow

### Stage 1 — Forensics (ThreatHunterAgent)
Parses raw, unstructured security logs and extracts structured incident data:
```json
{
  "incident_id": "INC-A1B2C3D4",
  "attack_type": "SQLi",
  "severity": "HIGH",
  "source_ips": ["198.51.100.23"],
  "confidence_score": 0.95
}
```

### Stage 2 — Policy Check (PolicyCheckerAgent)
Evaluates forensics against **zero-trust rules**:
- ✅ **PASSED** → External IP + HIGH/CRITICAL severity + known attack type
- ❌ **FAILED** → Internal RFC1918 IP / UNKNOWN source / low confidence

```json
{
  "incident_id": "INC-A1B2C3D4",
  "policy_check": "PASSED",
  "recommended_action": "BLOCK_IP_WAF_RULE",
  "policy_reasoning": "External IP confirmed SQLi attack with 95% confidence."
}
```

> ⛔ Pipeline **halts here** if `policy_check == FAILED`. No IaC is generated.

### Stage 3 — IaC Generation (CloudOpsRunnerAgent)
Generates production-ready **AWS WAFv2 Terraform** code:
```json
{
  "incident_id": "INC-A1B2C3D4",
  "script_type": "Terraform",
  "target_ips": ["198.51.100.23/32"],
  "code": "resource \"aws_wafv2_ip_set\" \"cloudguard_block_INC_A1B2C3D4\" { ... }"
}
```

### Stage 4 — Validation (ValidatorAgent)
Final safety gate before deployment. Blocks IaC containing:
- `/0` CIDR (blocks ALL internet traffic)
- `/1`–`/8` CIDR (blocks massive IP ranges)
- RFC1918 private IP blocks at WAF level

```json
{
  "incident_id": "INC-A1B2C3D4",
  "validation_status": "SAFE_TO_DEPLOY",
  "security_warnings": "None",
  "cidr_audit": {
    "total_cidrs_found": 1,
    "dangerous_cidrs": [],
    "safe_cidrs": ["198.51.100.23/32"]
  }
}
```

---

## 📡 Band API Integration

CloudGuard uses the **Band Agent API** as its real-time state machine and audit log.

| Endpoint | Usage |
|---|---|
| `GET /agent/me` | Verify API key on startup |
| `POST /agent/chats/{chat_id}/events` | Push structured pipeline state events |
| `POST /agent/chats/{chat_id}/messages` | Push human-readable summaries |
| `GET /agent/messages?status=processed` | Pull last known state |

Each pipeline stage pushes a `cloudguard.state.<STAGE>` event to the Band chat room, making the **entire incident timeline visible in the Band UI in real-time**.

---

## 🗂️ Project Structure

```
CloudGuard_AI/
├── band_layer/
│   ├── __init__.py
│   ├── band_client.py        # Band API HTTP client (push/pull)
│   └── state_manager.py      # CloudGuardOrchestrator — main pipeline
├── core_agents/
│   ├── __init__.py
│   ├── threat_hunter.py      # Stage 1: Forensic log parser
│   ├── policy_checker.py     # Stage 2: Zero-trust policy engine
│   ├── cloud_ops_runner.py   # Stage 3: Terraform IaC generator
│   └── validator.py          # Stage 4: CIDR safety auditor
├── frontend/                 # Demo web UI (Flask)
├── observability/            # Langfuse tracing integration
├── requirements.txt
└── .env                      # API keys (NOT committed)
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.11+
- A [Groq API key](https://console.groq.com/) (free tier works)
- A [Band AI](https://app.band.ai/) account + Agent API key

### 1. Clone the repository
```bash
git clone https://github.com/humayoon8180/CloudGuard.git
cd CloudGuard
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
Create a `.env` file in the project root:
```env
# LLM Provider
GROQ_API_KEY=your_groq_api_key_here

# Band AI Integration
BAND_API_KEY=your_band_agent_api_key_here
BAND_CHAT_ROOM_ID=your_band_chat_room_id_here   # Optional: enables live Band sync
```

> ⚠️ **Never commit your `.env` file.** It is listed in `.gitignore`.

---

## 🚀 Running CloudGuard

### Run the full pipeline (demo mode)
```bash
python -m band_layer.state_manager
```

This runs a sample SQLi attack log through all 4 stages.

### Run with a custom log
```bash
python -m band_layer.state_manager "2026-06-14T10:33:17Z WAF BLOCK clientIP=198.51.100.23 uri=/login args=username=admin'+OR+'1'='1 ruleId=SQLi-002"
```

### Run individual agents
```bash
# Test ThreatHunterAgent standalone
python -m core_agents.threat_hunter

# Test PolicyCheckerAgent standalone
python -m core_agents.policy_checker

# Test CloudOpsRunnerAgent standalone
python -m core_agents.cloud_ops_runner

# Test ValidatorAgent standalone
python -m core_agents.validator
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║  CloudGuard AI — Incident Response Pipeline Started                  ║
╚══════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════╗
║  Stage 1 / 4 — FORENSICS: ThreatHunter                              ║
╚══════════════════════════════════════════════════════════════════════╝
🔍 Running ThreatHunterAgent...
  [BandClient] → PUSH | state=FORENSICS | incident=INC-A1B2C3D4
  ✓ Forensics complete: {"incident_id": "INC-A1B2C3D4", "attack_type": "SQLi", ...}

╔══════════════════════════════════════════════════════════════════════╗
║  Stage 2 / 4 — POLICY CHECK: PolicyChecker                          ║
╚══════════════════════════════════════════════════════════════════════╝
🛡️ Running PolicyCheckerAgent...
  ✓ Policy decision: PASSED — BLOCK_IP_WAF_RULE

╔══════════════════════════════════════════════════════════════════════╗
║  Stage 3 / 4 — IAC GENERATION: CloudOpsRunner                       ║
╚══════════════════════════════════════════════════════════════════════╝
⚙️ Running CloudOpsRunnerAgent...
  ✓ Terraform generated — targets: ['198.51.100.23/32']

╔══════════════════════════════════════════════════════════════════════╗
║  Stage 4 / 4 — VALIDATION: Validator                                 ║
╚══════════════════════════════════════════════════════════════════════╝
🔎 Running ValidatorAgent...
  ✓ Validation: SAFE_TO_DEPLOY — warnings: None

🚀 Pipeline completed. IaC is SAFE TO DEPLOY.
```

---

## 🔐 Security Considerations

- **Zero-Trust by Design** — Every IP is treated as untrusted until verified external
- **RFC1918 Guard** — Internal IPs (`10.x`, `172.16.x`, `192.168.x`) are automatically rejected by PolicyChecker
- **CIDR Blast-Radius Protection** — ValidatorAgent blocks any broad CIDR (`/0`–`/8`) before deployment
- **No Credentials in Code** — All secrets managed via `.env` (strictly gitignored)

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| AI Agent Framework | [CrewAI](https://github.com/joaomdmoura/crewAI) |
| LLM | Groq — `llama-3.3-70b-versatile` |
| Agent Communication Hub | [Band AI](https://app.band.ai/) |
| IaC Target | AWS WAFv2 (Terraform) |
| Observability | Langfuse |
| Web UI | Flask |
| Language | Python 3.11+ |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🏆 Built For

**lablab.ai — Band of Agents Hackathon**
> *"Building the future of autonomous AI agent collaboration"*
