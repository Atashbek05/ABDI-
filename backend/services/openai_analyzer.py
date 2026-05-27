import json
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a cybersecurity threat analysis AI. Analyze the provided URL and page content for threats.

Respond ONLY with valid JSON in this exact format (no markdown fences):
{
  "threat_type": "<safe|phishing|malware|scam|fake_login|crypto_scam|suspicious>",
  "explanation": "<concise explanation, under 200 characters>",
  "confidence_score": <float 0.0 to 1.0>,
  "recommendation": "<brief user-facing recommendation>"
}

Evaluate based on:
- URL structure, domain patterns, suspicious TLDs, IP addresses
- Brand impersonation, urgency language, credential-harvesting forms
- Combinations that indicate phishing, malware delivery, or social engineering"""


class OpenAIAnalyzer:
    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable is not set")
            self._client = OpenAI(api_key=api_key)
            return self._client
        except Exception as e:
            logger.warning("OpenAI client init failed: %s", e)
            return None

    async def analyze(self, url: str, page_content: str = "") -> Dict:
        client = self._get_client()
        if client is None:
            return self._fallback()

        snippet = page_content[:1500] if page_content else "(no page content provided)"
        user_message = f"URL: {url}\n\nPage content sample:\n{snippet}"

        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=256,
                temperature=0.1,
                timeout=8,
            )
            raw = response.choices[0].message.content.strip()
            return self._parse(raw)
        except Exception as e:
            logger.warning("OpenAI analysis request failed: %s", e)
            return self._fallback()

    def _parse(self, raw: str) -> Dict:
        # Strip markdown code fences if the model wraps its output
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            data = json.loads(raw.strip())
            return {
                "threat_type": str(data.get("threat_type", "safe")),
                "explanation": str(data.get("explanation", ""))[:300],
                "confidence_score": round(min(1.0, max(0.0, float(data.get("confidence_score", 0.0)))), 3),
                "recommendation": str(data.get("recommendation", ""))[:300],
                "available": True,
            }
        except Exception:
            return self._fallback()

    @staticmethod
    def _fallback() -> Dict:
        return {
            "threat_type": "unknown",
            "explanation": "OpenAI analysis unavailable.",
            "confidence_score": 0.0,
            "recommendation": "Rely on the other detection layers for this result.",
            "available": False,
        }
