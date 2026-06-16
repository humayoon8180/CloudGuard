"""
CloudGuard AI - Policy Checker Agent
--------------------------------------
Evaluates forensic threat payloads against zero-trust security policies
and determines whether automated mitigation should be approved.

Output JSON Schema:
{
    "incident_id": "<from input>",
    "policy_check": "PASSED | FAILED",
    "recommended_action": "BLOCK_IP_WAF_RULE | ESCALATE_TO_SOC | NO_ACTION_REQUIRED",
    "policy_reasoning": "<brief explanation>"
}
"""

import json
from crewai import Agent, Task, Crew, Process
from dotenv import load_dotenv

from core_agents.base_agent import build_llm, extract_json, AGENT_DEFAULTS

load_dotenv()

_SYSTEM_PROMPT = """You are a strict Enterprise Cloud Compliance and Zero-Trust Policy Engine
running inside an automated incident response system. You evaluate structured threat forensics
against zero-trust security policies. Return ONLY a valid JSON object — no prose, no markdown.

ZERO-TRUST POLICY RULES:
1. PASSED (approve mitigation) if:
   - source_ips contains ONLY external, non-RFC1918 IP addresses, AND
   - severity is CRITICAL, HIGH, or MEDIUM, AND
   - attack_type is a known threat (SQLi, XSS, BruteForce, DDoS, RCE, PathTraversal).

2. FAILED (reject mitigation) if:
   - source_ips contains internal/RFC1918 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x).
   - source_ips is ["UNKNOWN"].
   - severity is LOW and confidence_score < 0.5.
   - attack_type is "Other" with confidence_score < 0.7.

STRICT OUTPUT FORMAT:
{
  "incident_id": "<from input>",
  "policy_check": "<PASSED|FAILED>",
  "recommended_action": "<BLOCK_IP_WAF_RULE|ESCALATE_TO_SOC|NO_ACTION_REQUIRED>",
  "policy_reasoning": "<one concise sentence>"
}

recommended_action values:
- BLOCK_IP_WAF_RULE: policy_check is PASSED, high-confidence external threat
- ESCALATE_TO_SOC: policy_check is FAILED but severity is CRITICAL (needs human review)
- NO_ACTION_REQUIRED: policy_check is FAILED, low severity or internal IP
"""


class PolicyCheckerAgent:
    """
    CrewAI agent that enforces zero-trust policies on forensic threat payloads.
    Outputs a structured approval/rejection decision for the CloudOps Runner.
    """

    def __init__(self):
        self.llm = build_llm(temperature=0.2)

    def _get_agent(self) -> Agent:
        return Agent(
            role="Enterprise Cloud Compliance & Zero-Trust Policy Reviewer",
            goal=(
                "Evaluate structured threat forensics against zero-trust security policies. "
                "Approve mitigation for confirmed external threats. Reject mitigation for "
                "internal IPs, whitelisted sources, or low-confidence alerts. "
                "Return ONLY a strict JSON decision object."
            ),
            backstory=(
                "You are a battle-tested Cloud Security Compliance Engine with encyclopedic "
                "knowledge of zero-trust architecture, RFC1918 private address spaces, and "
                "enterprise WAF policies. You make rapid, deterministic go/no-go decisions "
                "that authorize or block automated remediation actions. Your word is law — "
                "no human override exists for clearly external, high-severity threats."
            ),
            llm=self.llm,
            **AGENT_DEFAULTS,
        )

    def _get_task(self, threat_payload: dict, agent: Agent) -> Task:
        return Task(
            description=(
                f"Evaluate the following structured forensic threat payload against "
                f"zero-trust policies and output a policy decision.\n\n"
                f"FORENSIC PAYLOAD:\n{json.dumps(threat_payload, indent=2)}\n\n"
                f"SYSTEM INSTRUCTIONS:\n{_SYSTEM_PROMPT}"
            ),
            expected_output=(
                'A single valid JSON object with keys: '
                '"incident_id", "policy_check", "recommended_action", "policy_reasoning". '
                'No markdown, no explanation, no extra text.'
            ),
            agent=agent,
        )

    def run(self, threat_payload: dict) -> dict:
        """
        Executes the PolicyChecker CrewAI pipeline.

        Args:
            threat_payload: Structured forensic dict from ThreatHunterAgent.

        Returns:
            Policy decision dict with incident_id, policy_check,
            recommended_action, and policy_reasoning.

        Raises:
            ValueError: If the LLM output cannot be parsed as valid JSON.
        """
        agent = self._get_agent()
        task = self._get_task(threat_payload, agent)
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            memory=False,
        )
        result = crew.kickoff()
        return extract_json(result)


if __name__ == "__main__":
    import json
    sample_forensics = {
        "incident_id": "INC-A1B2C3D4",
        "attack_type": "SQLi",
        "severity": "HIGH",
        "source_ips": ["198.51.100.23"],
        "confidence_score": 0.95,
    }
    agent = PolicyCheckerAgent()
    output = agent.run(sample_forensics)
    print(json.dumps(output, indent=2))
