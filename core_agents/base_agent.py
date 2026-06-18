"""
CloudGuard AI - Base Agent
---------------------------
Shared foundation for all CloudGuard AI agents.

Provides:
  - A single shared LLM instance (groq/llama-3.3-70b-versatile)
  - Robust JSON extraction from raw LLM output
  - Consistent agent configuration (max_iter, timeouts)
"""

import os
import re
import json
import logging
from crewai import Agent, LLM

logger = logging.getLogger(__name__)

# ── Shared LLM instance (created once, reused by all agents) ──────────────────
# max_tokens kept at None to let Groq decide; temperature set per-agent.

def build_llm(temperature: float = 0.1) -> LLM:
    """
    Returns a CrewAI LLM instance pointed at Groq's llama-3.3-70b-versatile.
    Uses the OpenAI compatibility layer to bypass litellm's Groq routing bugs.

    Args:
        temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative).

    Returns:
        Configured LLM instance.
    """
    return LLM(
        model="openai/llama-3.3-70b-versatile",
        base_url="https://api.groq.com/openai/v1",
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=temperature,
    )


# ── Shared JSON extraction ─────────────────────────────────────────────────────

_JSON_FENCE_RE = re.compile(r"```(?:json)?", re.IGNORECASE)
_JSON_OBJ_RE   = re.compile(r"\{.*?\}", re.DOTALL)


def extract_json(raw_output) -> dict:
    """
    Robustly extracts the first valid JSON object from an LLM output.

    Handles:
      - Markdown code fences (```json ... ```)
      - Trailing prose after the JSON object
      - Objects with a .raw attribute (CrewAI CrewOutput)
      - Plain dict pass-through

    Args:
        raw_output: Raw output — str, dict, or CrewOutput object.

    Returns:
        Parsed dict.

    Raises:
        ValueError: If no valid JSON object can be found.
    """
    if isinstance(raw_output, dict):
        return raw_output

    raw_text = raw_output.raw if hasattr(raw_output, "raw") else str(raw_output)

    # Strip markdown fences
    cleaned = _JSON_FENCE_RE.sub("", raw_text).strip()

    # Find the first complete JSON object (non-greedy to avoid over-matching)
    match = _JSON_OBJ_RE.search(cleaned)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Last resort: try to parse the whole cleaned text
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    raise ValueError(
        f"No valid JSON object found in LLM output. "
        f"First 300 chars: {raw_text[:300]!r}"
    )


# ── Agent configuration defaults ──────────────────────────────────────────────

AGENT_DEFAULTS = {
    "verbose": True,
    "max_iter": 3,           # Limits ReAct loop depth → reduces Groq loop-detection errors
    "max_execution_time": 120,  # 2-minute hard timeout per agent
}
