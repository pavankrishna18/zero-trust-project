"""
LLM Threat Analysis Service (Phase 6)
======================================
Pipeline: Log -> Risk Engine -> LLM -> Natural Language Analysis -> Decision -> Store -> Display

Tries a chain of FREE LLM providers/models and falls back to the deterministic
rule-based engine (ai_explain.py) if every provider is unreachable, unconfigured,
or returns something we can't parse. No request ever hard-fails because of this.

Providers used (all have free tiers, no cost to run):
    1. Groq      — hosts Llama 3.2, Gemma 2/3, DeepSeek-R1-distill, Qwen 2.5 for free
    2. Gemini     — Google AI Studio free tier (gemini-1.5-flash)
    3. Ollama     — local, no API key needed, used if a local install is running

Configure via .env (all optional — missing keys are skipped silently):
    GROQ_API_KEY=...
    GEMINI_API_KEY=...
    OLLAMA_HOST=http://localhost:11434
"""

import os
import json
import logging
import requests

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

# Order follows the brief: Llama / Gemma first, DeepSeek R1 second, Qwen 2.5 third.
# NOTE: Groq retires/renames hosted models periodically — verify against
# console.groq.com/docs/models if any of these start returning 404/model_decommissioned.
GROQ_MODEL_CHAIN = [
    "llama-3.3-70b-versatile",       # Primary — Llama 3.x
    "gemma2-9b-it",                  # Primary alt — Gemma family
    "deepseek-r1-distill-llama-70b", # Secondary — DeepSeek R1
    "qwen/qwen3-32b",                # Third — Qwen (3.x is what Groq currently hosts)
]

# Local Ollama fallback chain — last resort, only used if a local install is running.
OLLAMA_MODEL_CHAIN = ["phi4-mini", "llama3.2", "qwen2.5"]

SYSTEM_PROMPT = """You are a Zero Trust Security Analyst.

You will be given structured signals about a device or IP address that has
been flagged or blocked. Analyze them like a SOC analyst would and respond
with STRICT JSON ONLY — no markdown, no code fences, no commentary — matching
exactly this schema:

{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "reason": "2-4 sentence natural-language explanation of why this is risky (or not)",
  "mitre_attack": [{"id": "Txxxx", "name": "Technique Name"}],
  "recommendation": "keep_blocked|reverify|unblock",
  "confidence": 0-100
}
"""


def _build_user_prompt(facts: dict) -> str:
    lines = ["Analyze this Zero Trust signal bundle:\n"]
    for k, v in facts.items():
        lines.append(f"- {k}: {v}")
    lines.append("\nReturn ONLY the JSON object described in the system prompt. No other text.")
    return "\n".join(lines)


def _extract_json(text: str):
    """LLMs sometimes wrap JSON in prose or code fences despite instructions — salvage it."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find('{')
    end = text.rfind('}')
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in LLM response")
    return json.loads(text[start:end + 1])


def _call_groq(model, timeout, user_prompt):
    if not GROQ_API_KEY:
        return None
    try:
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 500,
            },
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.info("Groq(%s) unavailable: HTTP %s", model, resp.status_code)
            return None
        content = resp.json()["choices"][0]["message"]["content"]
        return _extract_json(content), f"groq:{model}"
    except Exception as e:
        logger.info("Groq(%s) failed: %s", model, str(e))
        return None


def _call_gemini(timeout, user_prompt):
    if not GEMINI_API_KEY:
        return None
    model = "gemini-2.5-flash"
    try:
        url = GEMINI_URL.format(model=model, key=GEMINI_API_KEY)
        resp = requests.post(
            url,
            json={
                "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_prompt}]}],
                "generationConfig": {"temperature": 0.2},
            },
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.info("Gemini unavailable: HTTP %s", resp.status_code)
            return None
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return _extract_json(text), f"gemini:{model}"
    except Exception as e:
        logger.info("Gemini failed: %s", str(e))
        return None


def _call_ollama(model, timeout, user_prompt):
    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
            },
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        content = resp.json()["message"]["content"]
        return _extract_json(content), f"ollama:{model}"
    except Exception as e:
        logger.info("Ollama(%s) unavailable: %s", model, str(e))
        return None


def _normalize(raw_and_source):
    if not raw_and_source:
        return None
    raw, source = raw_and_source
    try:
        level = str(raw.get('threat_level', 'LOW')).upper()
        if level not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            level = 'LOW'

        mitre = raw.get('mitre_attack') or []
        mitre = [m for m in mitre if isinstance(m, dict) and m.get('id')]

        rec = raw.get('recommendation', 'reverify')
        if rec not in ('keep_blocked', 'reverify', 'unblock'):
            rec = 'reverify'
        rec_labels = {'keep_blocked': 'Keep blocked', 'reverify': 'Reverify device', 'unblock': 'Consider unblocking'}

        try:
            confidence = max(0, min(100, int(raw.get('confidence', 60))))
        except (TypeError, ValueError):
            confidence = 60

        reason_text = raw.get('reason') or 'No explanation provided by the model.'

        return {
            'risk_level': level,
            'reasons': [reason_text],
            'mitre': mitre,
            'recommendation': rec,
            'recommendation_label': rec_labels[rec],
            'confidence': confidence,
            'source': source,
        }
    except Exception as e:
        logger.warning("Failed to normalize LLM response from %s: %s", source, str(e))
        return None


def analyze_with_llm(facts: dict, timeout: int = 8):
    """
    Run the facts through the free-LLM fallback chain.
    Returns a normalized dict, or None if every provider failed/unconfigured
    (caller should fall back to the deterministic rule engine in that case).

    `timeout` is kept short (default 8s per call) so a click-to-open modal
    still feels fast even when walking through several providers.
    """
    user_prompt = _build_user_prompt(facts)

    for model in GROQ_MODEL_CHAIN:
        result = _normalize(_call_groq(model, timeout, user_prompt))
        if result:
            return result

    result = _normalize(_call_gemini(timeout, user_prompt))
    if result:
        return result

    for model in OLLAMA_MODEL_CHAIN:
        result = _normalize(_call_ollama(model, timeout, user_prompt))
        if result:
            return result

    logger.info("All LLM providers unavailable/unconfigured — caller should use rule-based fallback")
    return None
