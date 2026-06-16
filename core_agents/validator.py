"""
CloudGuard AI - Validator Agent
----------------------------------
Audits generated Terraform IaC code to ensure it does NOT contain
catastrophically broad CIDR blocks (/0, /8) that could cause production outages.

Output JSON Schema:
{
    "incident_id": "<from input>",
    "validation_status": "SAFE_TO_DEPLOY | BLOCKED_UNSAFE_CODE",
    "security_warnings": "None | <description of detected issues>",
    "cidr_audit": {
        "total_cidrs_found": 0,
        "dangerous_cidrs": [],
        "safe_cidrs": []
    }
}
"""

import json
from crewai import Agent, Task, Crew, Process
from dotenv import load_dotenv

from core_agents.base_agent import build_llm, extract_json, AGENT_DEFAULTS

load_dotenv()

_SYSTEM_PROMPT = """You are a meticulous Senior Cloud Security QA Engineer and IaC
Safety Auditor embedded in an automated deployment pipeline. You are the LAST line
of defense before infrastructure changes go live. Your job is to audit Terraform code
for catastrophic misconfigurations that could block entire internet ranges and take
down production systems. Return ONLY a valid JSON object — no prose, no markdown.

AUDIT RULES — BLOCK deployment if code contains:
1. CIDR ranges with prefix /0 (e.g., 0.0.0.0/0) — blocks ALL internet traffic.
2. CIDR ranges with prefix /1 through /8 — blocks massive IP ranges (entire countries/ISPs).
3. Private/RFC1918 CIDR blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) being blocked
   at a WAF level — this would break internal services.
4. Duplicate IP addresses in the same aws_wafv2_ip_set.

AUDIT RULES — PASS deployment if:
1. All CIDRs are /32 (single host blocks) or /24-/29 (small, targeted ranges).
2. No private RFC1918 addresses are present.
3. No broad network blocks (/0 through /8).

STRICT OUTPUT FORMAT:
{
  "incident_id": "<from input>",
  "validation_status": "<SAFE_TO_DEPLOY|BLOCKED_UNSAFE_CODE>",
  "security_warnings": "<None or description of each issue found>",
  "cidr_audit": {
    "total_cidrs_found": 0,
    "dangerous_cidrs": [],
    "safe_cidrs": []
  }
}
"""


class ValidatorAgent:
    """
    CrewAI agent that performs safety auditing on generated Terraform IaC.
    Acts as a circuit breaker — blocks deployment if catastrophic CIDRs are detected.
    """

    def __init__(self):
        self.llm = build_llm(temperature=0.0)

    def _get_agent(self) -> Agent:
        return Agent(
            role="Senior Cloud Security QA & IaC Safety Validator",
            goal=(
                "Audit generated Terraform IaC code for catastrophic CIDR misconfigurations. "
                "Detect and block any code containing /0 or /8 CIDR blocks that would cause "
                "massive network outages. Approve only precise, host-level /32 blocks. "
                "Return ONLY a strict JSON audit report."
            ),
            backstory=(
                "You are a legendary Cloud Security QA Lead who has prevented three "
                "production outages by catching malformed IP block rules before they "
                "were deployed. Your automated auditing runs as the final gate before "
                "any WAF rule goes live. You have zero tolerance for broad CIDR blocks — "
                "a single /0 rule has taken down Fortune 500 companies before."
            ),
            llm=self.llm,
            **AGENT_DEFAULTS,
        )

    def _get_task(self, iac_payload: dict, agent: Agent) -> Task:
        return Task(
            description=(
                f"Audit the following generated Terraform IaC payload for CIDR safety. "
                f"Detect any catastrophically broad network blocks.\n\n"
                f"IaC PAYLOAD:\n{json.dumps(iac_payload, indent=2)}\n\n"
                f"SYSTEM INSTRUCTIONS:\n{_SYSTEM_PROMPT}"
            ),
            expected_output=(
                'A single valid JSON object with keys: '
                '"incident_id", "validation_status" (SAFE_TO_DEPLOY or BLOCKED_UNSAFE_CODE), '
                '"security_warnings" (string), "cidr_audit" (object with total_cidrs_found, '
                'dangerous_cidrs, safe_cidrs). No markdown, no explanation, no extra text.'
            ),
            agent=agent,
        )

    def run(self, iac_payload: dict) -> dict:
        """
        Executes the Validator CrewAI pipeline.

        Args:
            iac_payload: IaC dict from CloudOpsRunnerAgent containing
                         Terraform HCL code to audit.

        Returns:
            Audit report dict with incident_id, validation_status,
            security_warnings, and cidr_audit details.

        Raises:
            ValueError: If the LLM output cannot be parsed as valid JSON.
        """
        agent = self._get_agent()
        task = self._get_task(iac_payload, agent)
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
    sample_iac = {
        "incident_id": "INC-A1B2C3D4",
        "script_type": "Terraform",
        "target_ips": ["198.51.100.23/32"],
        "code": (
            'resource "aws_wafv2_ip_set" "cloudguard_block_INC_A1B2C3D4" {\n'
            '  name               = "cloudguard-block-INC-A1B2C3D4"\n'
            '  scope              = "REGIONAL"\n'
            '  ip_address_version = "IPV4"\n'
            '  addresses          = ["198.51.100.23/32"]\n'
            "}"
        ),
    }
    agent = ValidatorAgent()
    output = agent.run(sample_iac)
    print(json.dumps(output, indent=2))
