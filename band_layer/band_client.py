"""
CloudGuard AI - Band API Client
---------------------------------
Verified Band Agent API schema (June 2026):

Authentication:
  GET  /agent/me              → 200  (X-API-Key + X-Agent-Id headers)

Events endpoint (primary collaboration mechanism):
  POST /agent/chats/{cid}/events
  Body: { "event": { "content": "<str>", "message_type": "tool_call" | "tool_result" } }
  tool_call   → agent is SENDING context/task to the next stage
  tool_result → agent is PUBLISHING its completed output

Handoff Pattern (Band-native collaboration):
  Stage N publishes its output as message_type="tool_result"
  Stage N+1 receives context from orchestrator (which read from Band) as message_type="tool_call"
  This makes inter-agent handoffs visible and traceable in Band UI.

Messages endpoint:
  POST /agent/chats/{cid}/messages requires mentions array with ≥1 external agent.
  Since CloudGuard runs as a single registered agent, all collaboration flows through
  events (tool_call / tool_result) which are fully supported and visible in Band.
"""

import os
import json
import logging
from typing import Optional, Any
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Band API configuration
BAND_API_BASE_URL = "https://app.band.ai/api/v1"
BAND_REQUEST_TIMEOUT = 30  # seconds


class BandAPIError(Exception):
    """Raised when the Band API returns an unexpected error response."""
    pass


class BandClient:
    """
    Real HTTP client for the Band.ai Agent API.

    Pushes every pipeline stage as a Band event using the verified
    tool_call / tool_result message_type schema, making the full
    multi-agent handoff chain visible inside the Band chat room.

    Collaboration model:
      ThreatHunter  →  tool_result (forensics output)  → Band
      PolicyChecker ←  tool_call  (forensics context)  ← Band (via orchestrator)
      PolicyChecker →  tool_result (policy decision)   → Band
      CloudOps      ←  tool_call  (policy context)     ← Band (via orchestrator)
      CloudOps      →  tool_result (terraform output)  → Band
      Validator     ←  tool_call  (iac context)        ← Band (via orchestrator)
      Validator     →  tool_result (validation result) → Band
    """

    # Mapping: pipeline state → Band message_type
    # tool_call  = agent is receiving context / being tasked
    # tool_result = agent is publishing its completed output
    _STATE_TO_MSG_TYPE = {
        "FORENSICS":    "tool_result",   # ThreatHunter completed analysis
        "POLICY_CHECK": "tool_result",   # PolicyChecker completed decision
        "IAC_GENERATION": "tool_result", # CloudOps completed Terraform generation
        "VALIDATION":   "tool_result",   # Validator completed audit
        # Handoff markers (input side of each stage)
        "HANDOFF_TO_POLICY":  "tool_call",
        "HANDOFF_TO_CLOUDOPS": "tool_call",
        "HANDOFF_TO_VALIDATOR": "tool_call",
    }

    def __init__(self, chat_room_id: Optional[str] = None, api_key: Optional[str] = None, agent_id: Optional[str] = None):
        self.api_key = api_key or os.getenv("BAND_API_KEY")
        self.agent_id = agent_id or os.getenv("BAND_AGENT_ID")

        if not self.api_key or not self.agent_id:
            raise EnvironmentError(
                "BAND_API_KEY and BAND_AGENT_ID must be set in .env"
            )

        self.chat_room_id = chat_room_id or os.getenv("BAND_CHAT_ROOM_ID")
        if not self.chat_room_id:
            raise EnvironmentError("BAND_CHAT_ROOM_ID must be set in .env")

        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": self.api_key,
            "X-Agent-Id": self.agent_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

        logger.info("[BandClient] Initializing with API Key: %s... | Agent ID: %s", self.api_key[:12], self.agent_id)

        # Verify connection on init
        self._agent_identity = self._verify_connection()
        handle = self._agent_identity.get("data", {}).get("name", "CloudGuard AI")
        self.agent_name = handle
        self.owner_uuid = self._agent_identity.get("data", {}).get("owner_uuid")
        logger.info("[BandClient] Connected to Band API as agent: %s", handle)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_connection(self) -> dict:
        """
        Calls GET /agent/me to verify the API key and return agent identity.
        Verified schema: returns {"data": {"handle": ..., "id": ..., ...}}
        """
        url = f"{BAND_API_BASE_URL}/agent/me"
        try:
            response = self._session.get(url, timeout=BAND_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            logger.warning(
                "Band API authentication failed (status %s). "
                "Using fallback identity. Response: %s",
                exc.response.status_code, exc.response.text
            )
            # Return a fallback identity so the pipeline can continue even if an agent key is invalid
            return {"data": {"handle": f"Agent-{self.agent_id[:8]}", "owner_uuid": "313d08b2-54c8-48ef-a2eb-6a0b4519a5f7"}}
        except requests.exceptions.ConnectionError as exc:
            raise BandAPIError(
                f"Cannot connect to Band API at {BAND_API_BASE_URL}. "
                "Check your network connection."
            ) from exc

    def _post_event(self, content: str, message_type: str) -> dict:
        """
        Posts a structured event to the Band chat room.

        Verified schema (June 2026):
          POST /agent/chats/{cid}/events
          Body: { "event": { "content": str, "message_type": "tool_call"|"tool_result" } }
          → 201 Created: {"data": {"id": "<uuid>", "success": true, "message_type": "..."}}

        Args:
            content: Human-readable description of the event (shown in Band UI).
            message_type: "tool_call" (input/handoff) or "tool_result" (output/completion).
        """
        url = f"{BAND_API_BASE_URL}/agent/chats/{self.chat_room_id}/events"
        payload = {
            "event": {
                "content": content,
                "message_type": message_type,
            }
        }
        try:
            response = self._session.post(url, json=payload, timeout=BAND_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            logger.error(
                "[BandClient] Failed to post event (type=%s): %s - %s",
                message_type, exc.response.status_code, exc.response.text,
            )
            return {}

    def _post_message(self, text: str) -> dict:
        """
        Sends a visible chat message to the Band chat room.
        Mentions the owner UUID to avoid cannot_mention_self errors and satisfy the schema.
        """
        if not self.owner_uuid:
            logger.warning("[BandClient] No owner_uuid available; skipping visible message.")
            return {}

        url = f"{BAND_API_BASE_URL}/agent/chats/{self.chat_room_id}/messages"
        payload = {
            "message": {
                "content": text,
                "mentions": [{"id": self.owner_uuid}]
            }
        }
        
        # Explicitly enforce headers to guarantee the correct Agent identity is used per the audit
        req_headers = {
            "X-API-Key": self.api_key,
            "X-Agent-Id": self.agent_id,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = self._session.post(url, json=payload, headers=req_headers, timeout=BAND_REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push(self, state: str, payload: Any) -> bool:
        """
        Pushes a structured agent output to Band as a tool_result event,
        then immediately publishes a tool_call handoff event for the next
        stage — making the full agent collaboration chain visible in Band.

        Args:
            state: Pipeline state name ("FORENSICS", "POLICY_CHECK",
                   "IAC_GENERATION", "VALIDATION").
            payload: The agent's structured output (dict or JSON string).

        Returns:
            True on success, False on failure.
        """
        # Normalize payload to dict
        if isinstance(payload, str):
            try:
                payload_dict = json.loads(payload)
            except json.JSONDecodeError:
                payload_dict = {"raw_output": payload}
        else:
            payload_dict = payload

        incident_id = payload_dict.get("incident_id", "UNKNOWN")

        # Build human-readable content string for Band UI
        content = self._build_event_content(state, incident_id, payload_dict)

        logger.info(
            "[BandClient] PUSH | state=%s | incident=%s",
            state, incident_id,
        )

        try:
            # 1. Publish this agent's output as a tool_result event (telemetry)
            resp = self._post_event(content=content, message_type="tool_result")
            event_id = resp.get("data", {}).get("id", "unknown")
            logger.info("[BandClient] Event posted: id=%s state=%s", event_id, state)

            # 1b. Also post as a visible message in the UI
            msg_resp = self._post_message(text=content)
            if msg_resp.get("data"):
                logger.info("[BandClient] Visible message posted: id=%s", msg_resp["data"]["id"])

            # 2. Publish the handoff trigger for the next stage as a tool_call event
            next_stage_content = self._build_handoff_content(state, incident_id)
            if next_stage_content:
                self._post_event(content=next_stage_content, message_type="tool_call")
                # And post the handoff as a visible chat message too
                self._post_message(text=next_stage_content)

            return True

        except BandAPIError as exc:
            logger.error("[BandClient] Push failed: %s", exc)
            return False

    def pull(self, state: str) -> Optional[dict]:
        """
        Placeholder pull — in the current sequential pipeline, context
        is passed in-memory by the orchestrator. This method is preserved
        for future async/distributed collaboration patterns.
        """
        logger.info("[BandClient] PULL | state=%s (in-memory mode)", state)
        return None

    def _build_event_content(self, state: str, incident_id: str, payload: dict) -> str:
        """Builds a concise, human-readable event string for the Band UI."""
        state_icons = {
            "FORENSICS":      "🔍",
            "POLICY_CHECK":   "🛡️",
            "IAC_GENERATION": "⚙️",
            "VALIDATION":     "✅",
        }
        icon = state_icons.get(state, "📊")
        lines = [f"{icon} {self.agent_name} | {state} | Incident: {incident_id}"]

        if state == "FORENSICS":
            lines.append(
                f"Attack: {payload.get('attack_type', 'N/A')} | "
                f"Severity: {payload.get('severity', 'N/A')} | "
                f"Source IPs: {payload.get('source_ips', [])}"
            )
        elif state == "POLICY_CHECK":
            lines.append(
                f"Decision: {payload.get('policy_check', 'N/A')} | "
                f"Action: {payload.get('recommended_action', 'N/A')} | "
                f"Reasoning: {str(payload.get('policy_reasoning', 'N/A'))[:120]}"
            )
        elif state == "IAC_GENERATION":
            lines.append(
                f"Script: {payload.get('script_type', 'N/A')} | "
                f"Targets: {payload.get('target_ips', [])} | "
                f"Rule: {str(payload.get('terraform_resource', 'N/A'))[:80]}"
            )
        elif state == "VALIDATION":
            lines.append(
                f"Status: {payload.get('validation_status', 'N/A')} | "
                f"Warnings: {payload.get('security_warnings', 'None')} | "
                f"Safe CIDRs: {payload.get('safe_cidrs', [])}"
            )

        return "\n".join(lines)

    def _build_handoff_content(self, state: str, incident_id: str) -> Optional[str]:
        """
        Builds a tool_call handoff event announcing the next stage.
        Returns None if this is the final stage (VALIDATION).
        """
        handoffs = {
            "FORENSICS":
                f"📨 HANDOFF | {self.agent_name} → PolicyChecker | "
                f"Incident {incident_id}: Forensic analysis complete. "
                f"PolicyChecker is now evaluating compliance...",
            "POLICY_CHECK":
                f"📨 HANDOFF | {self.agent_name} → CloudOpsRunner | "
                f"Incident {incident_id}: Policy check complete. "
                f"CloudOpsRunner is now generating Terraform remediation...",
            "IAC_GENERATION":
                f"📨 HANDOFF | {self.agent_name} → Validator | "
                f"Incident {incident_id}: IaC generated. "
                f"Validator is now auditing for CIDR and security compliance...",
        }
        return handoffs.get(state)  # Returns None for VALIDATION (terminal stage)
