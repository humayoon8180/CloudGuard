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

import os
import uuid
import json
import re
from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from dotenv import load_dotenv

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
        self.llm = ChatGroq(
            model_name="llama-3.3-70b-versatile",
            temperature=0.2,
        )

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
            verbose=True,
            llm=self.llm,
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

    @staticmethod
    def _extract_json(raw_output: str) -> dict:
        """
        Robustly extracts a JSON object from LLM output.
        Handles markdown fences, trailing prose, and whitespace.
        """
        # Strip markdown code fences
        cleaned = re.sub(r"```(?:json)?", "", raw_output).strip()
        # Find the first valid JSON object
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise ValueError(f"No valid JSON object found in output: {raw_output!r}")

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
        )
        result = crew.kickoff()
        raw_text = result.raw if hasattr(result, "raw") else str(result)
        return self._extract_json(raw_text)


if __name__ == "__main__":
    # Local smoke test
    sample_log = (
        "2026-06-14T10:33:17Z WAF BLOCK action=BLOCK "
        "clientIP=198.51.100.23 uri=/login "
        "args=username=admin'+OR+'1'='1 httpMethod=POST "
        "ruleId=SQLi-002 ruleGroup=AWSManagedRulesSQLiRuleSet"
    )
    agent = ThreatHunterAgent()
    output = agent.run(sample_log)
    print(json.dumps(output, indent=2))
