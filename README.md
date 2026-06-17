# 🛡️ CloudGuard AI

**Event-Driven Multi-Agent Cloud Security Operations Center (SOC)**
**Built for the Band of Agents Hackathon 2026**
**Track 3: Regulated & High-Stakes Workflows (Human-in-the-Loop)**

---

## 🚀 Catchy Project Overview
CloudGuard AI is a state-of-the-art, multi-agent AI Security Operations Center. It ingests raw network telemetry (like AWS WAF logs), performs deep forensic analysis, evaluates enterprise compliance policies, and dynamically generates Infrastructure-as-Code (Terraform) to mitigate active threats in real time. 

All agent collaboration and human-in-the-loop approvals are orchestrated securely and visibly through the **Band.ai** collaborative platform and a purpose-built real-time Flask Web Dashboard.

---

## ⚖️ Track 3 Justification (Regulated Workflows)
CloudGuard AI is custom-built for high-stakes enterprise environments where AI is strictly prohibited from unilaterally altering production cloud infrastructure. 
Instead of fully autonomous deployments, the pipeline explicitly terminates by locking the generated Terraform remediation code behind a strict **Human-in-the-Loop** approval gate on our Flask dashboard. Furthermore, the system employs a dedicated `ValidatorAgent` to enforce strict QA (like CIDR validation) before the code even reaches a human operator.

---

## 🏗️ Architecture & Agent Responsibilities
The system orchestrates four strictly isolated CrewAI agents via a central State Manager. 
**Crucially, `memory=False` is enforced on all agents** to guarantee zero hallucination during high-stakes IaC generation.

1. **Threat Hunter (`ThreatHunterAgent`)**: Parses unstructured security logs. Extracts attack signatures, malicious IPs, and assigns confidence scores.
2. **Policy Checker (`PolicyCheckerAgent`)**: Evaluates forensics against strict corporate compliance rules (e.g., ignoring internal IPs). Can halt the pipeline if the threat does not meet mitigation thresholds.
3. **CloudOps Engineer (`CloudOpsRunnerAgent`)**: Generates remediation scripts (Terraform/AWS WAF Rules) to isolate verified threats.
4. **DevOps Validator (`ValidatorAgent`)**: Audits the generated IaC for safety before presenting it for human approval.

---

## 🤝 Band.ai Collaboration Flow
Rather than acting as a black box, CloudGuard AI leverages **Dynamic Identity Routing** via the Band API to make multi-agent collaboration irrefutable.
- The Orchestrator hot-swaps `X-API-Key` and `X-Agent-Id` headers during runtime.
- As each stage completes, the responsible agent explicitly posts a `tool_result` event to the Band Chat Room.
- Each agent's message appears under their distinct Persona in the UI.
- **Band acts as the Collaboration Layer**, providing full visibility into the AI handoff chain.

---

## 🛠️ Setup Instructions & Environment Variables

### 1. Prerequisites
Ensure you have Python 3.10+ installed.

### 2. Installation
Create a virtual environment and install the strict dependencies:
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Environment Variables
Copy `.env.example` to `.env` and fill in your API keys:
```bash
cp .env.example .env
```
**Required Keys:**
- `GROQ_API_KEY`: For the Llama-3.3-70b inference engine.
- `BAND_API_KEY` / `BAND_AGENT_ID`: Main orchestrator identity.
- `BAND_THREAT_HUNTER_KEY` / `BAND_CLOUDOPS_KEY`: Specialized agent identities.
- `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY`: For enterprise telemetry.

---

## 🏁 Run & Demo Instructions

### Starting the System
Launch the Flask frontend dashboard, which automatically connects to Langfuse via LiteLLM:
```bash
python Fronted/app.py
```
Open your browser to `http://127.0.0.1:5000`. 

### The Demo Loop
1. The dashboard opens in an **IDLE** state.
2. Click **Simulate Threat (Scenario A)** to inject a simulated external SQLi attack.
3. Watch the WebSockets stream live updates as the four agents process the threat.
4. Concurrently, view your **Band Chat Room** to see the agents collaborating with distinct identities via `tool_result` events.
5. Once the pipeline completes, review the audited Terraform code and click **Approve & Deploy**.
*(Note: Scenarios B and C can be manually triggered in the backend for testing Policy Halts and Benign Traffic).*
