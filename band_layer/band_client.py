"""
CloudGuard AI - Band API Client (Real Implementation)
-------------------------------------------------------
Implements the actual HTTP communication layer between CloudGuard agents
and the Band.ai platform using the Band Agent API.

Band API Base URL: https://app.band.ai/api/v1
Authentication:   X-API-Key header (Agent API key from .env)

Key Endpoints Used:
- POST /agent/chats/{chat_id}/messages  → Push agent output as a message to the hub chat room
- GET  /agent/messages?status=pending   → Pull next unprocessed message from the queue
- POST /agent/chats/{chat_id}/events    → Push structured state events (non-message records)
- GET  /agent/me                        → Verify API key and get agent identity

Design Philosophy:
- Each pipeline "state" (FORENSICS, POLICY_CHECK, etc.) is published as a
  structured event to the Band chat room, making the entire incident timeline
  visible in the Band UI in real-time.
- Payloads are pushed as both events (for the audit log) and messages
  (for any downstream Band agent listeners).
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

    Handles authentication, pushing state payloads as events and messages,
    and pulling the latest state for a given incident from the chat room history.

    Usage:
        client = BandClient()
        client.push(state="FORENSICS", payload={"incident_id": "INC-...", ...})
        data = client.pull(state="FORENSICS")
    """

    def __init__(self, chat_room_id: Optional[str] = None):
        """
        Initializes the Band client.

        Args:
            chat_room_id: The Band chat room ID to use as the central state hub.
                          If None, reads from BAND_CHAT_ROOM_ID env var.
                          If still None, push/pull operate in logging-only mode.
        """
        self.api_key = os.getenv("BAND_API_KEY")
        if not self.api_key:
            raise EnvironmentError(
                "BAND_API_KEY is not set. "
                "Ensure it is defined in your .env file."
            )

        self.chat_room_id = chat_room_id or os.getenv("BAND_CHAT_ROOM_ID")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        # Verify connection on init
        self._agent_identity = self._verify_connection()
        logger.info(
            "[BandClient] Connected to Band API as agent: %s",
            self._agent_identity.get("handle", "unknown"),
        )
        print(
            f"  [BandClient] ✓ Connected to Band API. "
            f"Agent: {self._agent_identity.get('handle', 'CloudGuardAI')}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_connection(self) -> dict:
        """
        Calls GET /agent/me to verify the API key and return agent identity.

        Returns:
            Agent identity dict from the Band API.

        Raises:
            BandAPIError: If the API key is invalid or the request fails.
        """
        url = f"{BAND_API_BASE_URL}/agent/me"
        try:
            response = self._session.get(url, timeout=BAND_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            raise BandAPIError(
                f"Band API authentication failed (status {exc.response.status_code}). "
                f"Check your BAND_API_KEY. Response: {exc.response.text}"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise BandAPIError(
                f"Cannot connect to Band API at {BAND_API_BASE_URL}. "
                "Check your network connection."
            ) from exc

    def _post_event(self, event_type: str, data: dict) -> dict:
        """
        Posts a structured event to the Band chat room.
        Events are informational records (tool calls, results, state changes).

        Args:
            event_type: A string label for the event (e.g., "cloudguard.state.FORENSICS").
            data: The structured payload to attach to the event.

        Returns:
            The API response dict, or empty dict if chat_room_id is not configured.
        """
        if not self.chat_room_id:
            logger.warning(
                "[BandClient] No chat_room_id configured. "
                "Event '%s' logged locally only.", event_type
            )
            return {}

        url = f"{BAND_API_BASE_URL}/agent/chats/{self.chat_room_id}/events"
        payload = {
            "type": event_type,
            "data": data,
        }
        try:
            response = self._session.post(
                url, json=payload, timeout=BAND_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            logger.error(
                "[BandClient] Failed to post event '%s': %s - %s",
                event_type, exc.response.status_code, exc.response.text,
            )
            raise BandAPIError(
                f"Band API event POST failed (state={event_type}): "
                f"HTTP {exc.response.status_code} — {exc.response.text}"
            ) from exc

    def _post_message(self, text: str) -> dict:
        """
        Sends a text message to the Band chat room.
        Used to notify any human observers or downstream agents.

        Args:
            text: The message text to send.

        Returns:
            The API response dict, or empty dict if chat_room_id is not configured.
        """
        if not self.chat_room_id:
            return {}

        url = f"{BAND_API_BASE_URL}/agent/chats/{self.chat_room_id}/messages"
        payload = {"text": text}
        try:
            response = self._session.post(
                url, json=payload, timeout=BAND_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            logger.warning(
                "[BandClient] Message POST failed (non-critical): %s - %s",
                exc.response.status_code, exc.response.text,
            )
            # Non-critical: don't raise, events are the primary mechanism
            return {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push(self, state: str, payload: Any) -> bool:
        """
        Pushes a structured agent output to the Band API state machine.

        This posts the payload as a structured event to the chat room,
        creating an immutable audit trail. Also sends a human-readable
        summary message for visibility in the Band UI.

        Args:
            state: The pipeline state name (e.g., "FORENSICS", "POLICY_CHECK",
                   "IAC_GENERATION", "VALIDATION").
            payload: The agent's output. Can be a dict or a JSON string.

        Returns:
            True if the push succeeded, False if operating in offline mode.
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
        event_type = f"cloudguard.state.{state}"

        # Log locally always
        logger.info(
            "[BandClient] PUSH | state=%s | incident=%s | payload=%s",
            state, incident_id, json.dumps(payload_dict)[:200],
        )
        print(
            f"  [BandClient] → PUSH | state={state} | incident={incident_id}"
        )

        if not self.chat_room_id:
            print(
                f"  [BandClient]   ⚠  No BAND_CHAT_ROOM_ID set. "
                f"Payload logged locally (offline mode)."
            )
            return False

        try:
            # Post structured event (primary audit record)
            self._post_event(
                event_type=event_type,
                data={
                    "pipeline_state": state,
                    "incident_id": incident_id,
                    "agent_payload": payload_dict,
                },
            )

            # Post human-readable summary message
            summary = self._build_summary_message(state, incident_id, payload_dict)
            self._post_message(summary)

            print(f"  [BandClient]   ✓ Successfully pushed to Band API.")
            return True

        except BandAPIError as exc:
            logger.error("[BandClient] Push failed: %s", exc)
            print(f"  [BandClient]   ✗ Push failed: {exc}")
            return False

    def pull(self, state: str) -> Optional[dict]:
        """
        Pulls the latest state payload for a given pipeline state from Band API.

        Retrieves the agent's pending message queue to find the most recent
        output matching the requested state. In the CloudGuard sequential pipeline,
        this is used to verify the last pushed state before proceeding.

        Args:
            state: The pipeline state to retrieve (e.g., "FORENSICS").

        Returns:
            The most recent payload dict for that state, or None if not found.
        """
        logger.info("[BandClient] PULL | state=%s", state)
        print(f"  [BandClient] ← PULL | state={state}")

        if not self.chat_room_id:
            print(f"  [BandClient]   ⚠  No BAND_CHAT_ROOM_ID. Cannot pull from Band API.")
            return None

        url = f"{BAND_API_BASE_URL}/agent/messages"
        params = {"status": "processed", "limit": 50}

        try:
            response = self._session.get(
                url, params=params, timeout=BAND_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            messages = response.json()

            # Search for the most recent message matching this state
            target_event_type = f"cloudguard.state.{state}"
            if isinstance(messages, list):
                for msg in reversed(messages):
                    if msg.get("type") == target_event_type:
                        return msg.get("data", {}).get("agent_payload")

            logger.warning("[BandClient] No messages found for state=%s", state)
            return None

        except requests.exceptions.HTTPError as exc:
            logger.error(
                "[BandClient] Pull failed (state=%s): %s - %s",
                state, exc.response.status_code, exc.response.text,
            )
            return None

    @staticmethod
    def _build_summary_message(state: str, incident_id: str, payload: dict) -> str:
        """Builds a human-readable summary message for the Band chat room."""
        state_icons = {
            "FORENSICS": "🔍",
            "POLICY_CHECK": "🛡️",
            "IAC_GENERATION": "⚙️",
            "VALIDATION": "✅",
        }
        icon = state_icons.get(state, "📊")

        lines = [f"{icon} **CloudGuard AI** | State: `{state}` | Incident: `{incident_id}`"]

        if state == "FORENSICS":
            lines.append(
                f"Attack: `{payload.get('attack_type', 'N/A')}` | "
                f"Severity: `{payload.get('severity', 'N/A')}` | "
                f"IPs: `{payload.get('source_ips', [])}`"
            )
        elif state == "POLICY_CHECK":
            lines.append(
                f"Decision: `{payload.get('policy_check', 'N/A')}` | "
                f"Action: `{payload.get('recommended_action', 'N/A')}`"
            )
        elif state == "IAC_GENERATION":
            lines.append(
                f"Type: `{payload.get('script_type', 'N/A')}` | "
                f"Targets: `{payload.get('target_ips', [])}`"
            )
        elif state == "VALIDATION":
            lines.append(
                f"Status: `{payload.get('validation_status', 'N/A')}` | "
                f"Warnings: `{payload.get('security_warnings', 'None')}`"
            )

        return "\n".join(lines)
