"""Configurable local LLM adapter for air-gapped CryptaTrace deployments."""

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMConfig:
    base_url: str = os.environ.get("CRYPTATRACE_LLM_URL", "http://127.0.0.1:11434")
    model: str = os.environ.get("CRYPTATRACE_LLM_MODEL", "llama3.2")
    timeout_seconds: int = int(os.environ.get("CRYPTATRACE_LLM_TIMEOUT", "90"))


class LocalLLMError(RuntimeError):
    pass


def analyze(text: str, document_name: str, config: LLMConfig | None = None) -> str:
    settings = config or LLMConfig()
    prompt = (
        "You are the CryptaTrace offline document analyst. Analyze the supplied document. "
        "Return concise JSON with keys: classification, sensitivity, summary, risks, recommended_action. "
        "Do not invent facts. Document name: " + document_name + "\n\nDOCUMENT:\n" + text
    )
    payload = json.dumps({"model": settings.model, "prompt": prompt, "stream": False, "format": "json"}).encode("utf-8")
    request = urllib.request.Request(
        f"{settings.base_url.rstrip('/')}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=settings.timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LocalLLMError(f"Local LLM unavailable at {settings.base_url}: {error}") from error
    result = body.get("response")
    if not isinstance(result, str) or not result.strip():
        raise LocalLLMError("Local LLM returned no analysis")
    return result


def status(config: LLMConfig | None = None) -> dict[str, object]:
    settings = config or LLMConfig()
    try:
        request = urllib.request.Request(f"{settings.base_url.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
        models = [item.get("name") for item in data.get("models", [])]
        return {"online": True, "url": settings.base_url, "model": settings.model, "models": models}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {"online": False, "url": settings.base_url, "model": settings.model, "models": []}
