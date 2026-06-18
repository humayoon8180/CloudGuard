# 🛡️ CloudGuard AI

## AI-Powered Multi-Agent Cloud Security Operations Center

### Event-Driven Threat Detection, Compliance Validation & Human-Approved Cloud Remediation

**Band of Agents Hackathon 2026**
**Track 3: Regulated & High-Stakes Workflows**

---

# 🚀 Executive Summary

CloudGuard AI is an enterprise-grade, event-driven Security Operations Center (SOC) powered by collaborating AI agents.

The platform continuously analyzes cloud security telemetry, identifies active threats, validates them against compliance policies, generates Infrastructure-as-Code (Terraform) remediations, and routes every action through a mandatory Human-in-the-Loop approval process before deployment.

Unlike autonomous security systems that can introduce operational risk, CloudGuard AI is designed specifically for regulated environments where AI recommendations must remain transparent, auditable, and human-governed.

---

# 🎯 The Problem

Modern security teams face three critical challenges:

* Massive volumes of cloud security telemetry
* Alert fatigue caused by noisy detections
* Slow incident response during active attacks

Security analysts often spend valuable time manually:

1. Investigating attack indicators
2. Verifying policy compliance
3. Creating remediation rules
4. Reviewing infrastructure changes

This delay increases organizational exposure and operational risk.

---

# 💡 Our Solution

CloudGuard AI transforms incident response into a collaborative AI workflow.

Instead of a single monolithic AI model, specialized agents work together to:

✅ Detect threats from raw cloud logs

✅ Validate attacks against compliance policies

✅ Generate safe Terraform remediations

✅ Audit generated infrastructure changes

✅ Require explicit human approval before deployment

The result is a transparent, auditable, and enterprise-ready security automation pipeline.

---

# 🏆 Why This Fits Track 3

## Regulated & High-Stakes Workflow by Design

Cloud infrastructure modifications are inherently high-risk.

A single incorrect firewall rule can:

* Block legitimate users
* Disrupt production services
* Create compliance violations

For this reason, CloudGuard AI intentionally prevents autonomous deployment.

### Safety Layers

#### Layer 1: Policy Enforcement

The Policy Checker validates findings against organizational security policies.

#### Layer 2: Infrastructure Validation

The Validator Agent audits generated Terraform for correctness and safety.

#### Layer 3: Human-in-the-Loop Approval

No infrastructure change can be deployed without explicit operator approval through the dashboard.

This architecture ensures AI remains accountable, explainable, and governed.

---

# 🤖 Multi-Agent Architecture

CloudGuard AI uses four isolated CrewAI agents coordinated through a centralized state manager.

To minimize hallucination risk during infrastructure generation:

```python
memory=False
```

is enforced across all agents.

## 1️⃣ ThreatHunterAgent

### Mission

Analyze raw security telemetry.

### Responsibilities

* Parse AWS WAF logs
* Detect attack patterns
* Extract malicious IPs
* Identify attack vectors
* Assign confidence scores

### Output

Structured forensic intelligence

---

## 2️⃣ PolicyCheckerAgent

### Mission

Enforce enterprise compliance policies.

### Responsibilities

* Evaluate attack severity
* Ignore trusted/internal IP ranges
* Validate mitigation thresholds
* Prevent unnecessary remediation

### Output

Approve or halt workflow

---

## 3️⃣ CloudOpsRunnerAgent

### Mission

Generate cloud remediation actions.

### Responsibilities

* Create Terraform code
* Generate AWS WAF rules
* Produce deployable Infrastructure-as-Code

### Output

Terraform remediation package

---

## 4️⃣ ValidatorAgent

### Mission

Perform infrastructure QA.

### Responsibilities

* Validate CIDR blocks
* Verify Terraform syntax
* Detect unsafe configurations
* Prevent invalid deployments

### Output

Audited deployment artifact

---

# 🔄 End-to-End Workflow

```text
AWS WAF Logs
      │
      ▼
ThreatHunterAgent
      │
      ▼
PolicyCheckerAgent
      │
      ▼
CloudOpsRunnerAgent
      │
      ▼
ValidatorAgent
      │
      ▼
Human Approval Dashboard
      │
      ▼
Deploy
```

---

# 🤝 Band.ai Collaboration Layer

A key innovation of CloudGuard AI is the use of Band.ai as the collaboration fabric between agents.

Rather than operating as a black-box workflow, every handoff is visible and attributable.

## Dynamic Identity Routing

The orchestrator dynamically switches:

* X-API-Key
* X-Agent-Id

for each agent execution.

As tasks complete, agents publish structured:

```json
tool_result
```

events directly into the Band Chat Room.

This creates a real-time audit trail showing:

* Which agent performed each action
* What information was produced
* When handoffs occurred

Judges can observe the complete decision-making chain live.

---

# 📊 Real-Time Dashboard

The Flask dashboard serves as the operational command center.

### Features

* Live workflow visualization
* WebSocket event streaming
* Threat status tracking
* Terraform review panel
* Human approval controls
* Deployment readiness indicators

System state transitions:

```text
IDLE
 ↓
THREAT DETECTED
 ↓
ANALYZING
 ↓
VALIDATING
 ↓
AWAITING APPROVAL
 ↓
DEPLOYED
```

---

# 🛠️ Technology Stack

| Layer                     | Technology             |
| ------------------------- | ---------------------- |
| Multi-Agent Framework     | CrewAI                 |
| LLM Inference             | Llama 3.3 70B via Groq |
| Collaboration Layer       | Band.ai                |
| Backend                   | Flask                  |
| Real-Time Updates         | WebSockets             |
| Infrastructure Automation | Terraform              |
| Cloud Security            | AWS WAF                |
| Observability             | Langfuse               |
| LLM Gateway               | LiteLLM                |

---

# 🔐 Security & Reliability Principles

CloudGuard AI was designed around enterprise safety requirements.

### Principles

* Human approval required for deployment
* Agent isolation
* Infrastructure validation
* Compliance-first decisions
* Full auditability
* Explainable AI workflow
* Zero autonomous production changes

---

# ⚙️ Setup

## Prerequisites

* Python 3.10+
* Groq API Key
* Band.ai Credentials
* Langfuse Credentials

## Installation

```bash
git clone <repository>
cd CloudGuardAI

python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

---

# 🔑 Environment Variables

Create a `.env` file:

```bash
cp .env.example .env
```

Required variables:

```env
GROQ_API_KEY=

BAND_API_KEY=
BAND_AGENT_ID=

BAND_THREAT_HUNTER_KEY=
BAND_CLOUDOPS_KEY=

LANGFUSE_PUBLIC_KEY=
LANGFUSE_SECRET_KEY=
```

---

# ▶️ Running the Demo

Launch the dashboard:

```bash
python Frontend/app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

# 🎬 Demo Scenario

### Scenario A — External SQL Injection Attack

1. Open the dashboard
2. Click **Simulate Threat**
3. Observe live agent execution
4. Watch Band.ai display agent-to-agent collaboration
5. Review generated Terraform remediation
6. Approve deployment through the dashboard

### Expected Outcome

* Threat detected
* Compliance validated
* Terraform generated
* Infrastructure audited
* Human approval requested

---

# 🌟 What Makes CloudGuard AI Unique

✅ Multi-agent security operations

✅ Real-time AI collaboration visibility via Band.ai

✅ Infrastructure-as-Code remediation generation

✅ Compliance-aware decision making

✅ Human-in-the-Loop governance

✅ Enterprise-grade auditability

✅ Purpose-built for regulated environments

---

# 🔮 Future Roadmap

* Multi-cloud support (AWS, Azure, GCP)
* Automated threat intelligence enrichment
* SIEM integrations
* Kubernetes remediation workflows
* Security playbook generation
* Compliance frameworks (SOC 2, ISO 27001, PCI-DSS)

---

# 🏁 Closing Statement

CloudGuard AI demonstrates how multiple specialized AI agents can collaboratively accelerate security operations while preserving the governance, transparency, and human oversight required in high-stakes enterprise environments.

By combining CrewAI, Band.ai, Terraform, AWS security telemetry, and human approval gates, CloudGuard AI delivers a practical blueprint for the next generation of AI-assisted Security Operations Centers.
