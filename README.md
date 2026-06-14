# 🛡️ CloudGuard AI

![Hackathon](https://img.shields.io/badge/Hackathon-lablab.ai%20Band%20of%20Agents-blueviolet?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![CrewAI](https://img.shields.io/badge/CrewAI-Agents-orange?style=for-the-badge)
![Google Gemini](https://img.shields.io/badge/Google-Gemini%20API-blue?style=for-the-badge&logo=google)

**CloudGuard AI** is an Event-Driven Multi-Agent Cloud Security System that automatically investigates, approves, and remediates cloud security threats (such as AWS WAF logs) leveraging the power of Large Language Models (LLMs).

Built with ❤️ by **Team The Orchestrators** (Humayun, Danyal Fayaz, Rafay Khalil) for the [lablab.ai "Band of Agents" Hackathon](https://lablab.ai/).

---

## 🎯 Core Concept

Modern cloud security operations suffer from alert fatigue. Security Operation Centers (SOCs) are overwhelmed with raw logs and false positives, slowing down response times to critical threats. 

CloudGuard AI introduces a fully automated, agentic pipeline. Instead of relying on manual investigation, our system utilizes a coordinated group of AI agents to digest raw security events, evaluate them against your specific zero-trust policies, and generate infrastructure-as-code (IaC) to proactively block threats—all while validating the code to prevent production outages.

## 🧠 Multi-Agent Architecture

The core of CloudGuard AI is built around 4 highly specialized agents, powered by CrewAI. They do not communicate directly but instead operate via a central message hub (`Band API`), enforcing a strict, auditable pipeline:

1. **🕵️‍♂️ Threat Hunter**
   - **Role:** Parses raw, unstructured security data (e.g., AWS WAF logs).
   - **Action:** Extracts structured forensic JSON payloads detailing the threat.
2. **⚖️ Policy Checker**
   - **Role:** Evaluates the forensic payload against defined zero-trust security policies.
   - **Action:** Determines if automated mitigation should be approved or rejected.
3. **🛠️ CloudOps Runner**
   - **Role:** Acts upon approved policy decisions.
   - **Action:** Generates ready-to-deploy AWS WAF Terraform (IaC) blocks to block malicious IP sets.
4. **✅ Validator**
   - **Role:** Audits the generated Terraform code.
   - **Action:** Ensures the code does not contain catastrophically broad CIDR blocks (e.g., `/0`, `/8`) that could inadvertently cause network outages.

## 🛠️ Tech Stack

- **[Python](https://www.python.org/):** Core backend language.
- **[CrewAI](https://www.crewai.com/):** Multi-agent orchestration framework.
- **[Google Gemini API](https://deepmind.google/technologies/gemini/):** Powering the LLM intelligence of our specialized agents.
- **[Band API](https://codeband.ai/):** Providing the underlying communication layer, event push/pull state machine, and central hub for the agents.

## 🖥️ Frontend Architecture Note

**Note:** The backend agentic system defined in this repository operates independently as an intelligent core. The user interface (UI) is built separately and connects directly to this agentic backend via our Band API integration.

## 🚀 Setup & Installation

Follow these steps to get the CloudGuard AI agentic backend running locally.

### 1. Clone the Repository
```bash
git clone https://github.com/humayoon8180/CloudGuard.git
cd CloudGuard
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory and add your necessary API keys:

```env
# Example .env file
GEMINI_API_KEY="your_gemini_api_key_here"
BAND_API_KEY="your_band_api_key_here"
```

### 5. Run the Orchestrator
Execute the state manager to start the event-driven agent pipeline:
```bash
python -m band_layer.state_manager
```

---

*This project is submitted for the lablab.ai "Band of Agents" Hackathon. Feel free to explore the code!*
