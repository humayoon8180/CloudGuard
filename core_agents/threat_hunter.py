"""
CloudGuard AI - Threat Hunter Agent
------------------------------------
Parses raw, unstructured security/WAF logs and extracts structured
incident forensics as a strict JSON payload.

Output JSON Schema:
{
    "incident_id": "INC-<uuid-short>",
    "attack_type": "SQLi | XSS | BruteForce | DDoS | ...",
    "severity": "CRITICAL | HIGH | MEDIUM | LOW",
    "source_ips": ["x.x.x.x", ...],
    "confidence_score": 0.0-1.0
}
"""

import uuid
from crewai import Agent, Task, Crew, Process
from dotenv import load_dotenv

from core_agents.base_agent import build_llm, extract_json, AGENT_DEFAULTS

load_dotenv()

_SYSTEM_PROMPT = """You are an elite AWS Cloud Security Forensic Analyst embedded in an
automated incident response system. Your ONLY job is to parse raw security logs and
return a machine-readable JSON object. You must NEVER include explanations, markdown
fences, or prose. Return ONLY a valid JSON object.

STRICT OUTPUT FORMAT (no deviations):
{
  "incident_id": "INC-XXXXXXXX",
  "attack_type": "<SQLi|XSS|BruteForce|DDoS|RCE|PathTraversal|PortScan|Other>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "source_ips": ["x.x.x.x"],
  "confidence_score": 0.00
}

Rules:
- incident_id must follow the format "INC-" + 8 uppercase alphanumeric characters.
- severity is determined by: CRITICAL (active exploit, data exfil), HIGH (attack blocked, high volume),
  MEDIUM (scanning/probing), LOW (noise/single probe).
- confidence_score is a float between 0.0 and 1.0.
- source_ips must be a JSON array of strings, even if only one IP is found.
- If no IPs are found, use ["UNKNOWN"].
"""


class ThreatHunterAgent:
    """
    CrewAI agent that parses raw security logs into structured forensic JSON.
    Acts as the entry point of the CloudGuard incident response pipeline.
    """

    def __init__(self):
        self.llm = build_llm(temperature=0.2)

    def _get_agent(self) -> Agent:
        return Agent(
            role="Cloud Security Forensic Analyst",
            goal=(
                "Parse raw, unstructured AWS WAF and security logs. "
                "Extract attack type, severity classification, malicious source IPs, "
                "and a confidence score. Return ONLY a strict JSON object."
            ),
            backstory=(
                "You are a battle-hardened forensic investigator who has analyzed "
                "millions of AWS WAF, CloudTrail, and VPC Flow logs. You instantly "
                "recognize attack signatures—SQLi, XSS, brute-force, DDoS—and extract "
                "structured intelligence from raw log noise. You communicate exclusively "
                "through machine-readable JSON for downstream automated systems."
            ),
            llm=self.llm,
            **AGENT_DEFAULTS,
        )

    def _get_task(self, raw_log: str, agent: Agent) -> Task:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        return Task(
            description=(
                f"Analyze the following raw security log entry. "
                f"Assign it the incident ID: {incident_id}.\n\n"
                f"RAW LOG:\n{raw_log}\n\n"
                f"SYSTEM INSTRUCTIONS:\n{_SYSTEM_PROMPT}"
            ),
            expected_output=(
                'A single valid JSON object with keys: '
                '"incident_id", "attack_type", "severity", "source_ips", "confidence_score". '
                'No markdown, no explanation, no extra text.'
            ),
            agent=agent,
        )

    def run(self, raw_log: str) -> dict:
        """
        Executes the ThreatHunter CrewAI pipeline.

        Args:
            raw_log: Raw, unstructured security log string.

        Returns:
            Parsed forensic dict with incident_id, attack_type, severity,
            source_ips, and confidence_score.

        Raises:
            ValueError: If the LLM output cannot be parsed as valid JSON.
        """
        agent = self._get_agent()
        task = self._get_task(raw_log, agent)
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
    sample_log = (
        "2026-06-14T10:33:17Z WAF BLOCK action=BLOCK "
        "clientIP=198.51.100.23 uri=/login "
        "args=username=admin'+OR+'1'='1 httpMethod=POST "
        "ruleId=SQLi-002 ruleGroup=AWSManagedRulesSQLiRuleSet"
    )
    agent = ThreatHunterAgent()
    output = agent.run(sample_log)
    print(json.dumps(output, indent=2))
