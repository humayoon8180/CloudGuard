"""
CloudGuard AI - Cloud Ops Runner Agent
----------------------------------------
Converts approved policy decisions into deployable AWS WAF Terraform
Infrastructure-as-Code (IaC) blocks that block malicious IP sets.

Output JSON Schema:
{
    "incident_id": "<from input>",
    "script_type": "Terraform",
    "code": "<raw HCL terraform string>",
    "target_ips": ["x.x.x.x/32", ...]
}
"""

import json
from crewai import Agent, Task, Crew, Process
from dotenv import load_dotenv

from core_agents.base_agent import build_llm, extract_json, AGENT_DEFAULTS

load_dotenv()

_SYSTEM_PROMPT = """You are a senior DevSecOps Engineer and Terraform expert embedded in
an automated cloud remediation system. Your task is to generate production-grade,
deployable AWS WAF Terraform code to block malicious IP addresses.
Return ONLY a valid JSON object — no prose, no markdown fences outside the JSON.

TERRAFORM GENERATION RULES:
1. Use aws_wafv2_ip_set resource (NOT deprecated aws_waf_ipset).
2. Scope must be "REGIONAL" (for ALB/API Gateway WAFs).
3. All IPs in source_ips must be converted to /32 CIDR notation (e.g., "198.51.100.23" → "198.51.100.23/32").
4. Generate an aws_wafv2_web_acl_association block only as a comment placeholder.
5. Use descriptive resource names derived from incident_id (e.g., "cloudguard-block-INC-A1B2C3D4").
6. The "code" value must be a single escaped JSON string (\\n for newlines).

STRICT OUTPUT FORMAT:
{
  "incident_id": "<from input>",
  "script_type": "Terraform",
  "code": "<raw HCL terraform block as escaped string>",
  "target_ips": ["x.x.x.x/32", ...]
}

EXAMPLE Terraform code content (escaped in JSON):
resource \\"aws_wafv2_ip_set\\" \\"cloudguard_block_INC_XXXXXXXX\\" {\\n  name  = \\"cloudguard-block-INC-XXXXXXXX\\"\\n  scope = \\"REGIONAL\\"\\n  ip_address_version = \\"IPV4\\"\\n  addresses = [\\"x.x.x.x/32\\"]\\n  tags = {\\n    ManagedBy = \\"CloudGuardAI\\"\\n    IncidentID = \\"INC-XXXXXXXX\\"\\n  }\\n}
"""


class CloudOpsRunnerAgent:
    """
    CrewAI agent that generates AWS WAF Terraform blocks from approved security actions.
    Only activated when PolicyChecker returns policy_check = PASSED.
    """

    def __init__(self):
        self.llm = build_llm(temperature=0.1)

    def _get_agent(self) -> Agent:
        return Agent(
            role="Cloud Infrastructure-as-Code (IaC) Security Engineer",
            goal=(
                "Convert approved cloud security actions into valid, deployable "
                "Terraform HCL code targeting AWS WAFv2 IP sets. "
                "Generate precise, production-ready IaC — no placeholders, "
                "no commented-out code in the main resource blocks. "
                "Return ONLY a strict JSON object."
            ),
            backstory=(
                "You are a Principal DevSecOps Engineer who has automated the remediation "
                "of thousands of cloud security incidents using Terraform and AWS WAF. "
                "You write battle-tested IaC that is reviewed by automated validators "
                "before deployment. Every IP block you generate protects production "
                "infrastructure from real-world attackers."
            ),
            llm=self.llm,
            **AGENT_DEFAULTS,
        )

    def _get_task(self, incident_id: str, source_ips: list, agent: Agent) -> Task:
        """
        Builds the Terraform generation task.

        Args:
            incident_id: Unique incident identifier (e.g., "INC-A1B2C3D4").
            source_ips: List of malicious IPs to block (e.g., ["198.51.100.23"]).
            agent: The CrewAI agent to assign this task to.
        """
        context = {
            "incident_id": incident_id,
            "source_ips": source_ips,
        }
        return Task(
            description=(
                f"Generate an AWS WAFv2 Terraform ip_set block to block the following "
                f"confirmed malicious IP addresses.\n\n"
                f"APPROVED BLOCK REQUEST:\n{json.dumps(context, indent=2)}\n\n"
                f"SYSTEM INSTRUCTIONS:\n{_SYSTEM_PROMPT}"
            ),
            expected_output=(
                'A single valid JSON object with keys: '
                '"incident_id", "script_type" (must be "Terraform"), "code" (valid HCL as escaped string), '
                '"target_ips" (array of CIDR strings). '
                'No markdown, no explanation, no extra text.'
            ),
            agent=agent,
        )

    def run(self, policy_payload: dict) -> dict:
        """
        Executes the CloudOpsRunner CrewAI pipeline.

        Args:
            policy_payload: Approved policy decision dict from PolicyCheckerAgent.
                            Must have policy_check == "PASSED".
                            Reads "incident_id" and "source_ips" keys.

        Returns:
            IaC dict with incident_id, script_type, code (HCL), and target_ips.

        Raises:
            ValueError: If the LLM output cannot be parsed as valid JSON.
        """
        incident_id = policy_payload.get("incident_id", "UNKNOWN")
        # Extract source_ips: prefer from forensics merge, fallback to empty list
        source_ips = policy_payload.get("source_ips", [])

        agent = self._get_agent()
        task = self._get_task(incident_id, source_ips, agent)
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
    sample_policy = {
        "incident_id": "INC-A1B2C3D4",
        "policy_check": "PASSED",
        "recommended_action": "BLOCK_IP_WAF_RULE",
        "policy_reasoning": "External IP confirmed SQLi attack with 95% confidence.",
        "source_ips": ["198.51.100.23"],
    }
    agent = CloudOpsRunnerAgent()
    output = agent.run(sample_policy)
    print(json.dumps(output, indent=2))
